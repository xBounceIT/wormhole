// Windowless FreeRDP display adapter. Go owns profiles, credentials, tunnels,
// process lifetime and JSON framing. This executable only renders and sends input.
#include <freerdp/client.h>
#include <freerdp/client/disp.h>
#include <freerdp/client/cliprdr.h>
#include <freerdp/gdi/gdi.h>
#include <freerdp/input.h>
#include <freerdp/settings.h>
#include <winpr/synch.h>
#include <winpr/wlog.h>
#include <poll.h>
#include <signal.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "wire.h"
#include "clipboard.h"
#include "surface.h"

typedef struct {
  rdpClientContext common; // Required by FreeRDP's common channel handlers.
  DispClientContext* display;
  CliprdrClientContext* clipboard;
  int64_t clipboard_serial;
  BOOL clipboard_initialized;
  uint64_t display_max_area;
  UINT32 requested_width, requested_height;
  WhPaint paint;
  int certificate_cancelled;
  BOOL keys[512];
  UINT16 buttons;
  UINT16 x, y;
} Surface;

static UINT clipboard_formats(CliprdrClientContext* clip) {
  Surface* surface = clip->custom;
  if (!surface->paint.visible) return 0;
  CLIPRDR_FORMAT format = {13, NULL}; // CF_UNICODETEXT
  CLIPRDR_FORMAT_LIST list = {0};
  list.numFormats = 1; list.formats = &format;
  surface->clipboard_serial = wh_clipboard_serial();
  return clip->ClientFormatList(clip, &list);
}
static UINT clipboard_ready(CliprdrClientContext* clip, const CLIPRDR_MONITOR_READY* ready) {
  (void)ready;
  CLIPRDR_GENERAL_CAPABILITY_SET general = {0};
  general.capabilitySetType = CB_CAPSTYPE_GENERAL;
  general.capabilitySetLength = sizeof(general);
  general.version = CB_CAPS_VERSION_2;
  general.generalFlags = CB_USE_LONG_FORMAT_NAMES;
  CLIPRDR_CAPABILITIES capabilities = {0};
  capabilities.cCapabilitiesSets = 1;
  capabilities.capabilitySets = (CLIPRDR_CAPABILITY_SET*)&general;
  ((Surface*)clip->custom)->clipboard_initialized = TRUE;
  UINT result = clip->ClientCapabilities(clip, &capabilities);
  return result ? result : clipboard_formats(clip);
}
static UINT clipboard_list(CliprdrClientContext* clip, const CLIPRDR_FORMAT_LIST* list) {
  CLIPRDR_FORMAT_LIST_RESPONSE response = {0};
  response.common.msgFlags = CB_RESPONSE_OK;
  UINT result = clip->ClientFormatListResponse(clip, &response);
  if (result || !((Surface*)clip->custom)->paint.visible) return result;
  for (UINT32 i = 0; i < list->numFormats; ++i) {
    if (list->formats[i].formatId == 13) {
      CLIPRDR_FORMAT_DATA_REQUEST request = {0};
      request.requestedFormatId = 13;
      return clip->ClientFormatDataRequest(clip, &request);
    }
  }
  return 0;
}
static UINT clipboard_response(CliprdrClientContext* clip, const CLIPRDR_FORMAT_DATA_RESPONSE* response) {
  Surface* surface = clip->custom;
  if (surface->paint.visible && (response->common.msgFlags & CB_RESPONSE_OK)) {
    if (wh_clipboard_write(response->requestedFormatData, response->common.dataLen)) surface->clipboard_serial = wh_clipboard_serial();
  }
  return 0;
}
static UINT clipboard_request(CliprdrClientContext* clip, const CLIPRDR_FORMAT_DATA_REQUEST* request) {
  Surface* surface = clip->custom;
  size_t length = 0;
  unsigned char* text = NULL;
  if (surface->paint.visible && request->requestedFormatId == 13) text = wh_clipboard_read(&length);
  CLIPRDR_FORMAT_DATA_RESPONSE response = {0};
  response.common.msgFlags = text ? CB_RESPONSE_OK : CB_RESPONSE_FAIL;
  response.common.dataLen = (UINT32)length;
  response.requestedFormatData = text;
  UINT result = clip->ClientFormatDataResponse(clip, &response);
  if (text) { memset(text, 0, length); free(text); }
  return result;
}

static BOOL release_input(Surface* surface) {
  rdpInput* input = surface->common.context.input;
  for (UINT32 code = 1; code < 512; ++code) {
    if (surface->keys[code]) {
      if (!freerdp_input_send_keyboard_event_ex(input, FALSE, FALSE, code)) return FALSE;
      surface->keys[code] = FALSE;
    }
  }
  for (UINT16 flag = 0x1000; flag <= 0x4000; flag <<= 1) {
    if (surface->buttons & flag) {
      if (!freerdp_input_send_mouse_event(input, flag, surface->x, surface->y)) return FALSE;
    }
  }
  surface->buttons = 0;
  return TRUE;
}

static BOOL paint(rdpContext* context, UINT32 left, UINT32 top, UINT32 width, UINT32 height) {
  Surface* surface = (Surface*)context;
  rdpGdi* gdi = context->gdi;
  if (!wh_paint_begin(&surface->paint)) return TRUE;
  if (!gdi || !wh_valid_dimensions(gdi->width, gdi->height) ||
      left >= (UINT32)gdi->width || top >= (UINT32)gdi->height ||
      width > (UINT32)gdi->width - left || height > (UINT32)gdi->height - top) return FALSE;
  for (UINT32 y = top; y < top + height; y += WH_TILE_SIZE) {
    for (UINT32 x = left; x < left + width; x += WH_TILE_SIZE) {
      UINT32 w = left + width - x, h = top + height - y;
      if (w > WH_TILE_SIZE) w = WH_TILE_SIZE;
      if (h > WH_TILE_SIZE) h = WH_TILE_SIZE;
      const uint32_t header[7] = {2, gdi->width, gdi->height, x, y, w, h};
      if (!wh_write_header(stdout, header)) return FALSE;
      for (UINT32 row = 0; row < h; ++row) {
        const BYTE* pixels = gdi->primary_buffer + (size_t)(y + row) * gdi->stride + x * 4;
        if (fwrite(pixels, 4, w, stdout) != w) return FALSE;
      }
    }
  }
  const uint32_t end[7] = {3, surface->paint.pending};
  return wh_write_header(stdout, end) && fflush(stdout) == 0;
}

static BOOL begin_paint(rdpContext* context) {
  context->gdi->primary->hdc->hwnd->invalid->null = TRUE;
  return TRUE;
}
static BOOL end_paint(rdpContext* context) {
  HGDI_RGN invalid = context->gdi->primary->hdc->hwnd->invalid;
  if (invalid->null) return TRUE;
  return paint(context, invalid->x, invalid->y, invalid->w, invalid->h);
}
static BOOL resize_desktop(rdpContext* context) {
  UINT32 width = freerdp_settings_get_uint32(context->settings, FreeRDP_DesktopWidth);
  UINT32 height = freerdp_settings_get_uint32(context->settings, FreeRDP_DesktopHeight);
  if (!wh_valid_dimensions(width, height)) return FALSE;
  return gdi_resize(context->gdi, width, height);
}
static UINT update_display(Surface* surface) {
  if (!surface->display || !surface->display_max_area || !surface->requested_width) return 0;
  DISPLAY_CONTROL_MONITOR_LAYOUT monitor = {0};
  monitor.Width = surface->requested_width; monitor.Height = surface->requested_height;
  if (!wh_display_size(&monitor.Width, &monitor.Height, surface->display_max_area)) return 0;
  monitor.Flags = DISPLAY_CONTROL_MONITOR_PRIMARY;
  monitor.DesktopScaleFactor = 100; monitor.DeviceScaleFactor = 100;
  return surface->display->SendMonitorLayout(surface->display, 1, &monitor);
}
static UINT display_caps(DispClientContext* display, UINT32 monitors, UINT32 a, UINT32 b) {
  Surface* surface = display->custom;
  // One monitor only. Saturate the advertised product at our allocation bound.
  uint64_t area = (uint64_t)a * b;
  surface->display_max_area = monitors ? (area > WH_MAX_PIXELS ? WH_MAX_PIXELS : area) : 0;
  return update_display(surface);
}
static void channel_connected(void* context, const ChannelConnectedEventArgs* event) {
  Surface* surface = context;
  if (strcmp(event->name, CLIPRDR_SVC_CHANNEL_NAME) == 0) {
    surface->clipboard = event->pInterface;
    surface->clipboard->custom = surface;
    surface->clipboard->MonitorReady = clipboard_ready;
    surface->clipboard->ServerFormatList = clipboard_list;
    surface->clipboard->ServerFormatDataRequest = clipboard_request;
    surface->clipboard->ServerFormatDataResponse = clipboard_response;
  }
  else if (strcmp(event->name, DISP_DVC_CHANNEL_NAME) == 0) {
    surface->display = event->pInterface;
    surface->display->custom = surface;
    surface->display->DisplayControlCaps = display_caps;
  }
  else freerdp_client_OnChannelConnectedEventHandler(&surface->common, event);
}
static void channel_disconnected(void* context, const ChannelDisconnectedEventArgs* event) {
  Surface* surface = context;
  if (strcmp(event->name, CLIPRDR_SVC_CHANNEL_NAME) == 0) {
    if (surface->clipboard) surface->clipboard->custom = NULL;
    surface->clipboard = NULL;
    surface->clipboard_initialized = FALSE;
  }
  else if (strcmp(event->name, DISP_DVC_CHANNEL_NAME) == 0) {
    if (surface->display) surface->display->custom = NULL;
    surface->display = NULL;
    surface->display_max_area = 0;
  }
  else freerdp_client_OnChannelDisconnectedEventHandler(&surface->common, event);
}
static BOOL pre_connect(freerdp* instance) {
  return PubSub_SubscribeChannelConnected(instance->context->pubSub, channel_connected) >= 0 &&
         PubSub_SubscribeChannelDisconnected(instance->context->pubSub, channel_disconnected) >= 0;
}
static BOOL post_connect(freerdp* instance) {
  rdpContext* context = instance->context;
  ((Surface*)context)->paint.pending = 0;
  memset(((Surface*)context)->keys, 0, sizeof(((Surface*)context)->keys));
  ((Surface*)context)->buttons = 0;
  if (!wh_valid_dimensions(freerdp_settings_get_uint32(context->settings, FreeRDP_DesktopWidth),
                           freerdp_settings_get_uint32(context->settings, FreeRDP_DesktopHeight))) return FALSE;
  if (!gdi_init(instance, PIXEL_FORMAT_RGBA32)) return FALSE;
  context->update->BeginPaint = begin_paint;
  context->update->EndPaint = end_paint;
  context->update->DesktopResize = resize_desktop;
  const uint32_t connected[7] = {1};
  return wh_write_header(stdout, connected) && fflush(stdout) == 0;
}
static void post_disconnect(freerdp* instance) {
  PubSub_UnsubscribeChannelConnected(instance->context->pubSub, channel_connected);
  PubSub_UnsubscribeChannelDisconnected(instance->context->pubSub, channel_disconnected);
  gdi_free(instance);
}
static BOOL authenticate(freerdp* instance, char** username, char** password, char** domain, rdp_auth_reason reason) {
  (void)instance; (void)domain; (void)reason;
  return username && *username && (*username)[0] && password && *password;
}
static DWORD confirm_certificate(freerdp* instance, const char* host, const char* fingerprint) {
  Surface* surface = (Surface*)instance->context;
  if (surface->certificate_cancelled || !host || !fingerprint) return 0;
  size_t host_length = strnlen(host, 4097), fingerprint_length = strnlen(fingerprint, 4097);
  if (!host_length || host_length > 4096 || !fingerprint_length || fingerprint_length > 4096) return 0;
  const uint32_t header[7] = {4, (UINT32)host_length, (UINT32)fingerprint_length};
  if (!wh_write_header(stdout, header) || fwrite(host, 1, host_length, stdout) != host_length ||
      fwrite(fingerprint, 1, fingerprint_length, stdout) != fingerprint_length || fflush(stdout) != 0) return 0;
  uint32_t command[5];
  while (wh_read_command(stdin, command)) {
    int decision = wh_certificate_reply(&surface->certificate_cancelled, command);
    if (decision == 2) return 2; // Trust this connection only.
    if (decision == 0) break;
  }
  // Cancellation is terminal, including inside FreeRDP's reconnect loop. A late
  // answer to the closed dialog cannot approve a subsequent certificate prompt.
  surface->certificate_cancelled = 1;
  (void)freerdp_abort_connect_context(instance->context);
  return 0;
}
static DWORD verify_certificate(freerdp* instance, const char* host, UINT16 port, const char* common_name,
                               const char* subject, const char* issuer, const char* fingerprint, DWORD flags) {
  (void)port; (void)common_name; (void)subject; (void)issuer; (void)flags;
  return confirm_certificate(instance, host, fingerprint);
}
static DWORD verify_changed_certificate(freerdp* instance, const char* host, UINT16 port, const char* common_name,
                                       const char* subject, const char* issuer, const char* fingerprint,
                                       const char* old_subject, const char* old_issuer, const char* old_fingerprint, DWORD flags) {
  (void)old_subject; (void)old_issuer; (void)old_fingerprint;
  return verify_certificate(instance,host,port,common_name,subject,issuer,fingerprint,flags);
}
static BOOL client_new(freerdp* instance, rdpContext* context) {
  Surface* surface = (Surface*)context;
  surface->paint.visible = TRUE;
  instance->PreConnect = pre_connect;
  instance->PostConnect = post_connect;
  instance->PostDisconnect = post_disconnect;
  // context_new installs CLI callbacks by default. They must not read commands
  // from our binary stdin or open external authentication windows.
  instance->AuthenticateEx = authenticate;
  instance->ChooseSmartcard = NULL;
  instance->VerifyCertificateEx = verify_certificate;
  instance->VerifyChangedCertificateEx = verify_changed_certificate;
  instance->PresentGatewayMessage = NULL;
  instance->GetAccessToken = NULL;
  instance->RetryDialog = NULL;
  return TRUE;
}

static BOOL handle_command(Surface* surface, const uint32_t command[5]) {
  rdpContext* context = &surface->common.context;
  rdpInput* input = context->input;
  switch (command[0]) {
    case 1:
      if (!surface->paint.visible) return TRUE;
      surface->x = (UINT16)command[2]; surface->y = (UINT16)command[3];
      if (command[1] & 0x8000) surface->buttons |= command[1] & 0x7000;
      else surface->buttons &= ~(command[1] & 0x7000);
      return freerdp_input_send_mouse_event(input, command[1], surface->x, surface->y);
    case 2:
      if (!surface->paint.visible) return TRUE;
      surface->keys[command[1]] = command[2] != 0;
      return freerdp_input_send_keyboard_event_ex(input, command[2] != 0, FALSE, command[1]);
    case 3:
      if (!surface->paint.visible) return TRUE;
      return freerdp_input_send_unicode_keyboard_event(input, command[2] ? 0 : KBD_FLAGS_RELEASE, command[1]);
    case 4:
      surface->requested_width = command[1]; surface->requested_height = command[2];
      return update_display(surface) == 0;
    case 5:
      if (!wh_paint_show(&surface->paint)) return TRUE;
      return paint(context, 0, 0, context->gdi->width, context->gdi->height);
    case 6:
      surface->paint.visible = FALSE;
      return release_input(surface);
    case 7: return release_input(surface);
    case 8:
      if (wh_paint_ack(&surface->paint, command[1])) return paint(context, 0, 0, context->gdi->width, context->gdi->height);
      return TRUE;
    default: return FALSE;
  }
}

int main(void) {
  // stdout belongs exclusively to the pipe protocol; native diagnostics are never
  // forwarded to the renderer. Never invoke CLI prompts on this binary stdin.
  signal(SIGPIPE, SIG_IGN);
  setvbuf(stdin, NULL, _IONBF, 0);
  WLog_SetLogAppenderType(WLog_GetRoot(), WLOG_APPENDER_CONSOLE);
  WLog_ConfigureAppender(WLog_GetLogAppender(WLog_GetRoot()), "outputstream", "stderr");
  int argc = 0; char** argv = NULL;
  if (!wh_read_settings(stdin, &argc, &argv)) return 1;
  RDP_CLIENT_ENTRY_POINTS entry = {0};
  entry.Size = sizeof(entry); entry.Version = RDP_CLIENT_INTERFACE_VERSION;
  entry.ContextSize = sizeof(Surface); entry.ClientNew = client_new;
  rdpContext* context = freerdp_client_context_new(&entry);
  if (!context) { wh_free_settings(argc, argv); return 1; }
  int parsed = freerdp_client_settings_parse_command_line(context->settings, argc, argv, FALSE);
  wh_free_settings(argc, argv);
  if (parsed < 0 ||
      !freerdp_settings_set_bool(context->settings, FreeRDP_UseCommonStdioCallbacks, FALSE) ||
      !freerdp_settings_set_bool(context->settings, FreeRDP_SoftwareGdi, TRUE) ||
      freerdp_client_start(context) != 0) {
    freerdp_client_context_free(context); return 1;
  }
  BOOL connected = freerdp_connect(context->instance);
  int result = connected ? 0 : 1;
  while (connected && !freerdp_shall_disconnect_context(context)) {
    HANDLE handles[64];
    DWORD count = freerdp_get_event_handles(context, handles, 64);
    if (!count || WaitForMultipleObjects(count, handles, FALSE, 10) == WAIT_FAILED) { result = 1; break; }
    if (!freerdp_check_event_handles(context)) {
      if (client_auto_reconnect(context->instance)) continue;
      result = 1; break;
    }
    Surface* surface = (Surface*)context;
    if (surface->paint.visible && surface->clipboard && surface->clipboard_initialized && surface->clipboard_serial != wh_clipboard_serial()) {
      if (clipboard_formats(surface->clipboard) != 0) { result = 1; break; }
    }
    for (unsigned batch = 0; batch < 256; ++batch) {
      struct pollfd descriptor = {STDIN_FILENO, POLLIN, 0};
      if (poll(&descriptor, 1, 0) < 0) { result = 1; connected = FALSE; break; }
      if (!(descriptor.revents & (POLLIN | POLLHUP | POLLERR))) break;
      uint32_t command[5];
      if (!wh_read_command(stdin, command)) { connected = FALSE; break; }
      if (!handle_command(surface, command)) { result = 1; connected = FALSE; break; }
    }
  }
  freerdp_disconnect(context->instance);
  freerdp_client_stop(context);
  freerdp_client_context_free(context);
  return result;
}
