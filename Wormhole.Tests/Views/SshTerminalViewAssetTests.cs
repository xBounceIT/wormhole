using System;
using System.IO;
using Xunit;

namespace Wormhole.Tests.Views;

public sealed class SshTerminalViewAssetTests
{
    [Fact]
    public void Initialization_MasksButDoesNotCollapseWebView()
    {
        var xaml = ReadAsset("SshTerminalView.xaml");
        var code = ReadAsset("SshTerminalView.xaml.cs.txt");

        var webViewIndex = xaml.IndexOf("<controls:WebView2", StringComparison.Ordinal);
        Assert.True(webViewIndex >= 0, "The terminal WebView2 must remain declared in the view.");

        var maskIndex = xaml.IndexOf("<Border x:Name=\"TerminalContentMask\"", StringComparison.Ordinal);
        Assert.True(maskIndex > webViewIndex, "The terminal mask must render above WebView2.");

        var maskEndIndex = xaml.IndexOf("/>", maskIndex, StringComparison.Ordinal);
        Assert.True(maskEndIndex > maskIndex, "The terminal mask declaration must be complete.");

        var baseCoverIndex = xaml.IndexOf("<!-- Base cover:", StringComparison.Ordinal);
        Assert.True(baseCoverIndex > maskEndIndex, "Status overlays must remain above the terminal mask.");
        Assert.Contains("Visibility=\"Visible\"", xaml[maskIndex..maskEndIndex], StringComparison.Ordinal);

        const string visibleAssignment = "TerminalView.Visibility = Visibility.Visible;";
        const string collapsedAssignment = "TerminalView.Visibility = Visibility.Collapsed;";
        const string unloadMethod = "OnUnloaded(object sender";

        var unloadIndex = code.IndexOf(unloadMethod, StringComparison.Ordinal);
        var collapsedIndex = code.IndexOf(collapsedAssignment, StringComparison.Ordinal);

        Assert.Contains(visibleAssignment, code, StringComparison.Ordinal);
        Assert.True(unloadIndex >= 0, "The unload lifecycle hook must remain present.");
        Assert.True(
            collapsedIndex > unloadIndex,
            "WebView2 may be collapsed only after entering OnUnloaded; initialization needs real bounds.");
        Assert.Equal(
            collapsedIndex,
            code.LastIndexOf(collapsedAssignment, StringComparison.Ordinal));
        Assert.Contains(
            "TerminalContentMask.Visibility = Visibility.Visible;",
            code,
            StringComparison.Ordinal);
        Assert.Contains(
            "TerminalContentMask.Visibility = Visibility.Collapsed;",
            code,
            StringComparison.Ordinal);
    }

    [Fact]
    public void Initialization_DisablesBrowserAcceleratorsBeforeNavigation()
    {
        var code = ReadAsset("SshTerminalView.xaml.cs.txt");

        var settingsIndex = code.IndexOf(
            "Settings.AreBrowserAcceleratorKeysEnabled = false;",
            StringComparison.Ordinal);
        var navigateIndex = code.IndexOf(
            "core.Navigate(_activeHandshakeSource);",
            StringComparison.Ordinal);

        Assert.True(settingsIndex >= 0, "WebView2 browser accelerators must be disabled for terminal input.");
        Assert.True(navigateIndex > settingsIndex, "Accelerators must be disabled before loading xterm.");
    }

    [Fact]
    public void ProcessFailure_ReloadsRendererAndDetachesDeadOutputSink()
    {
        var code = ReadAsset("SshTerminalView.xaml.cs.txt");

        var subscriptionIndex = code.IndexOf(
            "ProcessFailed += OnTerminalProcessFailed;",
            StringComparison.Ordinal);
        var navigateIndex = code.IndexOf(
            "core.Navigate(_activeHandshakeSource);",
            StringComparison.Ordinal);
        Assert.True(subscriptionIndex >= 0 && subscriptionIndex < navigateIndex);
        Assert.Contains("CoreWebView2ProcessFailedKind.RenderProcessExited", code, StringComparison.Ordinal);
        Assert.Contains("CoreWebView2ProcessFailedKind.RenderProcessUnresponsive", code, StringComparison.Ordinal);
        Assert.Contains("RouteTerminalRendererFailureAsync(vm, failureMessage)", code, StringComparison.Ordinal);
        Assert.Contains("NavigateTerminalPage(core, bindingGeneration)", code, StringComparison.Ordinal);
        Assert.Contains("RecreateTerminalWebViewAfterBrowserExit()", code, StringComparison.Ordinal);
        Assert.Contains("CoreWebView2ProcessFailedKind.BrowserProcessExited", code, StringComparison.Ordinal);
        Assert.Contains("handshakeGeneration != _handshakeGeneration", code, StringComparison.Ordinal);
        Assert.Contains("args.Source, _activeHandshakeSource", code, StringComparison.Ordinal);
        Assert.Contains("IsRendererRecoveryCurrent(recoveryGeneration, vm, bindingGeneration)", code, StringComparison.Ordinal);
        Assert.Contains("TryTakeTerminalRendererRecoveryRequest", code, StringComparison.Ordinal);
        Assert.DoesNotContain(
            "TryParseTerminalSizeFrame(msg, \"r:\"",
            code,
            StringComparison.Ordinal);
        Assert.Contains("if (!vm.OwnsTerminalRenderer(sender))", code, StringComparison.Ordinal);
        Assert.Contains(
            "Failed to attach the terminal renderer: ",
            code,
            StringComparison.Ordinal);
        Assert.DoesNotContain("newVm.ReportFailure(ex.Message)", code, StringComparison.Ordinal);
        Assert.DoesNotContain("vm.ReportFailure(ex.Message)", code, StringComparison.Ordinal);
    }

    [Fact]
    public void BrowserExitAndConcurrentInitialization_CannotReuseRetiredWebView()
    {
        var code = ReadAsset("SshTerminalView.xaml.cs.txt");

        var recoveryEntryIndex = code.IndexOf(
            "private async Task FailProtocolSessionAndResetRendererAsync(",
            StringComparison.Ordinal);
        var persistentFlagIndex = code.IndexOf(
            "_terminalWebViewRecreationRequired = true;",
            recoveryEntryIndex,
            StringComparison.Ordinal);
        var recoveryCasIndex = code.IndexOf(
            "CompareExchange(ref _rendererRecoveryInProgress",
            recoveryEntryIndex,
            StringComparison.Ordinal);
        Assert.True(
            recoveryEntryIndex >= 0 &&
            persistentFlagIndex > recoveryEntryIndex &&
            recoveryCasIndex > persistentFlagIndex,
            "Browser replacement must be persisted before entering a possibly busy recovery.");

        var attachReplacementIndex = code.IndexOf(
            "if (_terminalWebViewRecreationRequired)",
            StringComparison.Ordinal);
        var firstCoreReadIndex = code.IndexOf(
            "TerminalView.CoreWebView2",
            StringComparison.Ordinal);
        Assert.True(
            attachReplacementIndex >= 0 && attachReplacementIndex < firstCoreReadIndex,
            "A closed WebView must be replaced before any CoreWebView2 access.");

        Assert.Contains(
            "if (!ReferenceEquals(sender, _subscribedProcessCore)) return;",
            code,
            StringComparison.Ordinal);
        Assert.Contains(
            "_initializationRequested = true;",
            code,
            StringComparison.Ordinal);
        Assert.Contains(
            "var initializingView = TerminalView;",
            code,
            StringComparison.Ordinal);
        Assert.Contains(
            "webViewGeneration == _webViewGeneration",
            code,
            StringComparison.Ordinal);
        Assert.Contains(
            "retiringRendererIdentity as CoreWebView2",
            code,
            StringComparison.Ordinal);
        Assert.Contains(
            ".LogDebug(ex, \"Terminal WebView was already closed during unload.\");",
            code,
            StringComparison.Ordinal);
    }

    [Fact]
    public void BrowserReplacement_IsTransactionalAndRollbackPreservesManualRetry()
    {
        var code = ReadAsset("SshTerminalView.xaml.cs.txt");
        var methodStart = code.IndexOf(
            "private void RecreateTerminalWebViewAfterBrowserExit()",
            StringComparison.Ordinal);
        var methodEnd = code.IndexOf(
            "private static WebView2 CreateConfiguredTerminalWebView(",
            methodStart,
            StringComparison.Ordinal);
        var transaction = code[methodStart..methodEnd];

        var createIndex = transaction.IndexOf(
            "var replacement = CreateConfiguredTerminalWebView(failedView);",
            StringComparison.Ordinal);
        var insertIndex = transaction.IndexOf(
            "TerminalRoot.Children.Insert(childIndex + 1, replacement);",
            StringComparison.Ordinal);
        var removeOldIndex = transaction.IndexOf(
            "TerminalRoot.Children.RemoveAt(childIndex);",
            StringComparison.Ordinal);
        var rollbackIndex = transaction.IndexOf(
            "RollbackTerminalWebViewReplacement(failedView, childIndex, replacement);",
            StringComparison.Ordinal);
        var commitIndex = transaction.IndexOf(
            "TerminalView = replacement;",
            StringComparison.Ordinal);
        var generationIndex = transaction.IndexOf(
            "_webViewGeneration++;",
            StringComparison.Ordinal);
        var coreCommitIndex = transaction.IndexOf(
            "_subscribedProcessCore = null;",
            StringComparison.Ordinal);
        var gateCommitIndex = transaction.IndexOf(
            "_initializationRecoveryGate.OnReplacementSucceeded();",
            StringComparison.Ordinal);
        var closeOldIndex = transaction.IndexOf(
            "CloseTerminalWebViewBestEffort(failedView);",
            StringComparison.Ordinal);

        Assert.True(createIndex >= 0 && insertIndex > createIndex);
        Assert.True(removeOldIndex > insertIndex && rollbackIndex > removeOldIndex);
        Assert.True(commitIndex > rollbackIndex);
        Assert.True(generationIndex > commitIndex && coreCommitIndex > generationIndex);
        Assert.True(gateCommitIndex > coreCommitIndex && closeOldIndex > gateCommitIndex);
        Assert.DoesNotContain(
            "_subscribedProcessCore = null;",
            transaction[..commitIndex],
            StringComparison.Ordinal);
        Assert.DoesNotContain(
            "failedView.Close()",
            transaction[..commitIndex],
            StringComparison.Ordinal);

        var rollbackStart = methodEnd;
        var rollbackEnd = code.IndexOf(
            "private static void CloseTerminalWebViewBestEffort(",
            rollbackStart,
            StringComparison.Ordinal);
        var helpers = code[methodEnd..rollbackEnd];
        Assert.Contains("var replacement = new WebView2();", helpers, StringComparison.Ordinal);
        Assert.Contains("CloseTerminalWebViewBestEffort(replacement);", helpers, StringComparison.Ordinal);
        Assert.Contains("TerminalRoot.Children.IndexOf(replacement)", helpers, StringComparison.Ordinal);
        Assert.Contains("TerminalRoot.Children.IndexOf(failedView) < 0", helpers, StringComparison.Ordinal);
        Assert.Contains("TerminalRoot.Children.Insert(", helpers, StringComparison.Ordinal);
    }

    [Fact]
    public void InitializationLatch_RebindHandoffTargetsCurrentLoadedBinding()
    {
        var code = ReadAsset("SshTerminalView.xaml.cs.txt");
        var methodStart = code.IndexOf(
            "private async Task InitializeWebViewAsync()",
            StringComparison.Ordinal);
        var methodEnd = code.IndexOf(
            "private bool IsCurrentInitialization(",
            methodStart,
            StringComparison.Ordinal);
        var initialization = code[methodStart..methodEnd];
        var finallyIndex = initialization.LastIndexOf("finally", StringComparison.Ordinal);
        var currentTargetIndex = initialization.IndexOf(
            "var currentTargetIsAvailable =",
            finallyIndex,
            StringComparison.Ordinal);
        var retryDecisionIndex = initialization.IndexOf(
            "_initializationRecoveryGate.ShouldConsumeInitializationRetry(",
            currentTargetIndex,
            StringComparison.Ordinal);
        var restartIndex = initialization.IndexOf(
            "await InitializeWebViewAsync().ConfigureAwait(true);",
            retryDecisionIndex,
            StringComparison.Ordinal);

        Assert.True(finallyIndex >= 0 && currentTargetIndex > finallyIndex);
        Assert.True(retryDecisionIndex > currentTargetIndex && restartIndex > retryDecisionIndex);
        Assert.DoesNotContain(
            "initializationOwnerIsCurrent",
            initialization[finallyIndex..restartIndex],
            StringComparison.Ordinal);
        Assert.Contains("IsLoaded &&", initialization[currentTargetIndex..retryDecisionIndex], StringComparison.Ordinal);
        Assert.Contains("_viewModel is not null &&", initialization[currentTargetIndex..retryDecisionIndex], StringComparison.Ordinal);
        Assert.Contains(
            "ReferenceEquals(_viewModel, DataContext);",
            initialization[currentTargetIndex..retryDecisionIndex],
            StringComparison.Ordinal);
        Assert.Contains(
            "_terminalWebViewRecreationRequired," + Environment.NewLine +
            "                    currentTargetIsAvailable))",
            initialization[retryDecisionIndex..restartIndex],
            StringComparison.Ordinal);
    }

    [Fact]
    public void InitializationFailureAfterCoreCreation_ForcesFreshWebViewOnRetry()
    {
        var code = ReadAsset("SshTerminalView.xaml.cs.txt");
        var methodStart = code.IndexOf(
            "private async Task InitializeWebViewAsync()",
            StringComparison.Ordinal);
        var methodEnd = code.IndexOf(
            "private bool IsCurrentInitialization(",
            methodStart,
            StringComparison.Ordinal);
        var initialization = code[methodStart..methodEnd];

        var armIndex = initialization.IndexOf(
            "replaceViewOnInitializationFailure = true;",
            StringComparison.Ordinal);
        var ensureIndex = initialization.IndexOf(
            "await initializingView.EnsureCoreWebView2Async(environment);",
            StringComparison.Ordinal);
        var catchIndex = initialization.IndexOf(
            "catch (Exception ex)",
            ensureIndex,
            StringComparison.Ordinal);
        var recreateIndex = initialization.IndexOf(
            "_terminalWebViewRecreationRequired = true;",
            catchIndex,
            StringComparison.Ordinal);
        var reportIndex = initialization.IndexOf(
            "await RouteTerminalRendererFailureAsync(vm,",
            catchIndex,
            StringComparison.Ordinal);

        Assert.True(
            armIndex >= 0 && armIndex < ensureIndex,
            "The possibly destructive CoreWebView2 creation phase must arm fresh-control recovery.");
        Assert.True(
            catchIndex > ensureIndex &&
            recreateIndex > catchIndex &&
            reportIndex > recreateIndex,
            "A post-Ensure failure must require a fresh WebView before exposing Retry.");
    }

    [Fact]
    public void PreOwnershipBrowserRecovery_IsBoundedAndUsesALocalRetryOverlay()
    {
        var xaml = ReadAsset("SshTerminalView.xaml");
        var code = ReadAsset("SshTerminalView.xaml.cs.txt");

        var disconnectedActionIndex = xaml.IndexOf(
            "Content=\"Reconnect\"",
            StringComparison.Ordinal);
        var localOverlayIndex = xaml.IndexOf(
            "x:Name=\"TerminalRendererRetryOverlay\"",
            StringComparison.Ordinal);
        var gridEndIndex = xaml.LastIndexOf("</Grid>", StringComparison.Ordinal);
        Assert.True(
            localOverlayIndex > disconnectedActionIndex && localOverlayIndex < gridEndIndex,
            "The local renderer retry overlay must be the final layer above VM status overlays.");
        Assert.Contains(
            "Click=\"OnRetryTerminalRendererClick\"",
            xaml,
            StringComparison.Ordinal);

        Assert.Contains(
            "_initializationRecoveryGate.OnUnownedBrowserProcessExited()",
            code,
            StringComparison.Ordinal);
        Assert.Contains(
            "TerminalBrowserExitAction.RequireManualRetry",
            code,
            StringComparison.Ordinal);
        Assert.Contains(
            "_initializationRecoveryGate.ShouldConsumeInitializationRetry(",
            code,
            StringComparison.Ordinal);
        Assert.Contains(
            "_initializationRecoveryGate.OnReplacementSucceeded();",
            code,
            StringComparison.Ordinal);
        Assert.Contains(
            "_initializationRecoveryGate.TryQueueManualRetry()",
            code,
            StringComparison.Ordinal);
        Assert.Contains(
            "CompleteLocalRendererRecovery();",
            code,
            StringComparison.Ordinal);
        Assert.Contains(
            "await retiringViewModel.DetachViewAsync(",
            code,
            StringComparison.Ordinal);
        Assert.Contains(
            "vm.DetachView(core, preserveTerminalContents: false);",
            code,
            StringComparison.Ordinal);
    }

    [Fact]
    public void RendererRecovery_RequiresCurrentLifecycleAndCommittedOwnership()
    {
        var code = ReadAsset("SshTerminalView.xaml.cs.txt");

        Assert.Contains("if (IsCommittedRendererOwner(requestedVm))", code, StringComparison.Ordinal);
        Assert.Contains(
            "await RetryAttachWithFreshWebViewAsync(requestedVm, failureMessage)",
            code,
            StringComparison.Ordinal);

        var failureIndex = code.IndexOf(
            "var vmRecoveryLease = await RouteTerminalRendererFailureAsync(vm, failureMessage)",
            StringComparison.Ordinal);
        var lifecycleCheckIndex = code.IndexOf(
            "!vm.IsTerminalRendererRecoveryCurrent(acceptedRecoveryLease)",
            failureIndex,
            StringComparison.Ordinal);
        var detachIndex = code.IndexOf(
            "vm.DetachView(core, preserveTerminalContents: false);",
            failureIndex,
            StringComparison.Ordinal);

        Assert.True(failureIndex >= 0, "Renderer failure recovery must return a lifecycle lease.");
        Assert.True(
            lifecycleCheckIndex > failureIndex && lifecycleCheckIndex < detachIndex,
            "A stale recovery must be rejected before detaching a replacement renderer.");
        Assert.Contains(
            "recoveryResult == RendererRecoveryResult.Busy",
            code,
            StringComparison.Ordinal);
    }

    [Fact]
    public void RendererFailureRouting_IsAtomicAndKeepsOtherViewsLocal()
    {
        var code = ReadAsset("SshTerminalView.xaml.cs.txt");

        Assert.DoesNotContain(
            ".HandleTerminalRendererFailureAsync(",
            code,
            StringComparison.Ordinal);

        var routerStart = code.IndexOf(
            "private async Task<TerminalRendererRecoveryLease?> RouteTerminalRendererFailureAsync(",
            StringComparison.Ordinal);
        var routerEnd = code.IndexOf(
            "private void TryRemoveInitializationMessageHandler(",
            routerStart,
            StringComparison.Ordinal);
        Assert.True(routerStart >= 0 && routerEnd > routerStart);
        var router = code[routerStart..routerEnd];

        var atomicTryIndex = router.IndexOf(
            "vm.TryHandleTerminalRendererFailureAsync(",
            StringComparison.Ordinal);
        var identityIndex = router.IndexOf(
            "TryGetTerminalRendererIdentity()",
            StringComparison.Ordinal);
        var rejectedIndex = router.IndexOf(
            "if (recoveryLease is null)",
            StringComparison.Ordinal);
        var localRetryIndex = router.IndexOf(
            "RequireLocalRendererRetry();",
            rejectedIndex,
            StringComparison.Ordinal);
        Assert.True(
            atomicTryIndex >= 0 &&
            identityIndex > atomicTryIndex &&
            rejectedIndex > identityIndex &&
            localRetryIndex > rejectedIndex,
            "Every renderer failure must be scoped to this view and rejection must remain local.");

        var recoveryCoreStart = code.IndexOf(
            "private async Task<RendererRecoveryResult> FailProtocolSessionAndResetRendererCoreAsync(",
            StringComparison.Ordinal);
        var recoveryCoreEnd = code.IndexOf(
            "private bool IsRendererRecoveryCurrent(",
            recoveryCoreStart,
            StringComparison.Ordinal);
        var recoveryCore = code[recoveryCoreStart..recoveryCoreEnd];
        var routedFailureIndex = recoveryCore.IndexOf(
            "RouteTerminalRendererFailureAsync(vm, failureMessage)",
            StringComparison.Ordinal);
        var detachIndex = recoveryCore.IndexOf(
            "vm.DetachView(core, preserveTerminalContents: false);",
            StringComparison.Ordinal);
        Assert.True(
            routedFailureIndex >= 0 && detachIndex > routedFailureIndex,
            "Protocol teardown must be authorized by the atomic renderer-scoped API first.");
    }

    [Fact]
    public void PageReuse_AwaitsOrderedBridgeRetirement()
    {
        var code = ReadAsset("SshTerminalView.xaml.cs.txt");

        var bindingStart = code.IndexOf(
            "private async Task AttachCurrentViewModelAsync()",
            StringComparison.Ordinal);
        var bindingEnd = code.IndexOf(
            "if (newVm is null) return;",
            bindingStart,
            StringComparison.Ordinal);
        var bindingPath = code[bindingStart..bindingEnd];
        var detachIndex = bindingPath.IndexOf(
            "await retiringViewModel.DetachViewAsync(",
            StringComparison.Ordinal);
        var handlerRemovalIndex = bindingPath.IndexOf(
            "TryRemoveInitializationMessageHandler(retiringCore);",
            StringComparison.Ordinal);
        var ownershipCommitIndex = bindingPath.IndexOf(
            "_viewModel = newVm;",
            StringComparison.Ordinal);
        Assert.True(
            detachIndex >= 0 &&
            handlerRemovalIndex > detachIndex &&
            ownershipCommitIndex > handlerRemovalIndex,
            "A recycled page must finish the outgoing bridge retirement before its handlers and owner change.");

        var recoveryStart = code.IndexOf(
            "private async Task<RendererRecoveryResult> FailProtocolSessionAndResetRendererCoreAsync(",
            StringComparison.Ordinal);
        var recoveryEnd = code.IndexOf(
            "private bool IsRendererRecoveryCurrent(",
            recoveryStart,
            StringComparison.Ordinal);
        var recoveryPath = code[recoveryStart..recoveryEnd];
        var recoveryDetachIndex = recoveryPath.IndexOf(
            "await vm.DetachViewAsync(",
            StringComparison.Ordinal);
        var recoveryNavigateIndex = recoveryPath.IndexOf(
            "NavigateTerminalPage(core, bindingGeneration)",
            StringComparison.Ordinal);
        Assert.True(
            recoveryDetachIndex >= 0 && recoveryNavigateIndex > recoveryDetachIndex,
            "A live renderer recovery must retire the old page before navigating it.");

        var unloadStart = code.IndexOf(
            "OnUnloaded(object sender",
            StringComparison.Ordinal);
        var unloadPath = code[unloadStart..];
        var unloadDetachIndex = unloadPath.IndexOf(
            "await retiringViewModel.DetachViewAsync(",
            StringComparison.Ordinal);
        var unloadHandlerRemovalIndex = unloadPath.IndexOf(
            "TryRemoveInitializationMessageHandler(",
            StringComparison.Ordinal);
        Assert.True(
            unloadDetachIndex >= 0 && unloadHandlerRemovalIndex > unloadDetachIndex,
            "Unload must preserve the parser listener until the accepted output prefix retires.");
    }
    [Fact]
    public void EveryAttachPath_PushesWinUiFocusBeforeTheJsFocusBarrier()
    {
        var code = ReadAsset("SshTerminalView.xaml.cs.txt");

        Assert.Contains("TerminalView.Focus(FocusState.Programmatic);", code, StringComparison.Ordinal);

        var reattachStart = code.IndexOf("if (_handshakeReceived)", StringComparison.Ordinal);
        var reattachEnd = code.IndexOf(
            "await InitializeWebViewAsync().ConfigureAwait(true);",
            reattachStart,
            StringComparison.Ordinal);
        var reattachPath = code[reattachStart..reattachEnd];
        var reattachFocusIndex = reattachPath.IndexOf(
            "TryFocusTerminalHost();",
            StringComparison.Ordinal);
        var reattachCallIndex = reattachPath.IndexOf(
            "await newVm.AttachAsync(",
            StringComparison.Ordinal);
        Assert.True(
            reattachFocusIndex >= 0 && reattachCallIndex > reattachFocusIndex,
            "A live terminal reattach must focus the WebView host before AttachAsync.");

        var readyPathStart = code.IndexOf("vm.UpdateTerminalSize(size);", StringComparison.Ordinal);
        var readyPathEnd = code.IndexOf(
            "TryRemoveInitializationMessageHandler(sender);",
            readyPathStart,
            StringComparison.Ordinal);
        var readyPath = code[readyPathStart..readyPathEnd];
        var readyFocusIndex = readyPath.IndexOf(
            "TryFocusTerminalHost();",
            StringComparison.Ordinal);
        var readyAttachIndex = readyPath.IndexOf(
            "await vm.AttachAsync(",
            StringComparison.Ordinal);
        Assert.True(
            readyFocusIndex >= 0 && readyAttachIndex > readyFocusIndex,
            "The first terminal handshake must focus the WebView host before AttachAsync.");
    }

    [Fact]
    public void RecoveryLogging_IsNonThrowingBeforeRendererStateChanges()
    {
        var code = ReadAsset("SshTerminalView.xaml.cs.txt");

        Assert.Contains(
            "new NonThrowingLogger<SshTerminalView>(logger)",
            code,
            StringComparison.Ordinal);
        Assert.Contains(
            "_logger = ResolveLogger();",
            code,
            StringComparison.Ordinal);
        Assert.DoesNotContain("logger?.Log", code, StringComparison.Ordinal);

        var processFailureIndex = code.IndexOf(
            "private async void OnTerminalProcessFailed",
            StringComparison.Ordinal);
        var warningIndex = code.IndexOf(
            "_logger.LogWarning(",
            processFailureIndex,
            StringComparison.Ordinal);
        var stateChangeIndex = code.IndexOf(
            "_handshakeReceived = false;",
            processFailureIndex,
            StringComparison.Ordinal);
        Assert.True(
            warningIndex > processFailureIndex && warningIndex < stateChangeIndex,
            "The pre-recovery diagnostic must use the non-throwing logger.");
    }

    private static string ReadAsset(string fileName) =>
        File.ReadAllText(Path.Combine(AppContext.BaseDirectory, "Views", "Sessions", fileName));
}
