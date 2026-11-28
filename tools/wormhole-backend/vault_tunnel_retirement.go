package main

// A bounded close attempt is not exit proof. The isolated controller retains
// ownership until Wait confirms the original sidecar has terminated. Main must
// quarantine this controller instead of force-killing it on a cleanup timeout.
// A missing exit channel deliberately cannot acknowledge retirement.
func retireSealedTunnel(process *tunnelProcess) {
	if process == nil {
		return
	}
	process.close()
	<-process.exited
}

func waitSealedTunnel(process *tunnelProcess) {
	_ = process.command.Wait()
	// ExitError still carries an OS process state. A failed wait without one
	// cannot establish termination, even if Kill or pipe closure succeeded.
	if process.command.ProcessState != nil {
		close(process.exited)
	}
}
