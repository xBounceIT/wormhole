-- 0013_serial_protocol: PuTTY-style serial-port terminal settings.
-- Host stores the serial line name (COM1, COM10, \\.\COM10, etc.) for Protocol=Serial.

ALTER TABLE Nodes ADD COLUMN SerialBaudRate INTEGER NULL;
ALTER TABLE Nodes ADD COLUMN SerialDataBits INTEGER NULL;
ALTER TABLE Nodes ADD COLUMN SerialStopBits INTEGER NULL;
ALTER TABLE Nodes ADD COLUMN SerialParity INTEGER NULL;
ALTER TABLE Nodes ADD COLUMN SerialFlowControl INTEGER NULL;
