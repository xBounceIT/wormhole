namespace Wormhole.Models;

public enum SerialParityMode
{
    None = 0,
    Odd = 1,
    Even = 2,
    Mark = 3,
    Space = 4,
}

public enum SerialStopBitsMode
{
    One = 1,
    Two = 2,
    OnePointFive = 3,
}

public enum SerialFlowControlMode
{
    None = 0,
    XonXoff = 1,
    RtsCts = 2,
    DsrDtr = 3,
}

public static class SerialDefaults
{
    public const int BaudRate = 9600;
    public const int DataBits = 8;
    public const SerialStopBitsMode StopBits = SerialStopBitsMode.One;
    public const SerialParityMode Parity = SerialParityMode.None;
    public const SerialFlowControlMode FlowControl = SerialFlowControlMode.None;

    public static int NormalizeBaudRate(int? value) =>
        value is > 0 ? value.Value : BaudRate;

    public static int NormalizeDataBits(int? value) =>
        value is >= 5 and <= 8 ? value.Value : DataBits;

    public static SerialStopBitsMode NormalizeStopBits(SerialStopBitsMode? value) =>
        value is SerialStopBitsMode.One or SerialStopBitsMode.Two or SerialStopBitsMode.OnePointFive
            ? value.Value
            : StopBits;

    public static SerialParityMode NormalizeParity(SerialParityMode? value) =>
        value is SerialParityMode.None or SerialParityMode.Odd or SerialParityMode.Even
            or SerialParityMode.Mark or SerialParityMode.Space
            ? value.Value
            : Parity;

    public static SerialFlowControlMode NormalizeFlowControl(SerialFlowControlMode? value) =>
        value is SerialFlowControlMode.None or SerialFlowControlMode.XonXoff
            or SerialFlowControlMode.RtsCts or SerialFlowControlMode.DsrDtr
            ? value.Value
            : FlowControl;
}
