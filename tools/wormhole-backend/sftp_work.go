package main

import "sync"

// The sealed child bounds and joins background file work before exiting. Legacy
// servers keep their existing scheduling until their lifecycle is migrated.
type sftpWorkGroup struct {
	mu     sync.Mutex
	wg     sync.WaitGroup
	active int
	closed bool
}

const sealedSFTPWorkLimit = 32
const sealedSFTPTransferLimit = 8

func (server *sshServer) startSftpWork(work func()) bool {
	group := server.sftpWork
	if group == nil {
		go work()
		return true
	}
	group.mu.Lock()
	defer group.mu.Unlock()
	if group.closed || group.active >= sealedSFTPWorkLimit {
		return false
	}
	group.active++
	group.wg.Add(1)
	go func() {
		defer group.wg.Done()
		defer func() { group.mu.Lock(); group.active--; group.mu.Unlock() }()
		work()
	}()
	return true
}

func (group *sftpWorkGroup) stop() {
	group.mu.Lock()
	group.closed = true
	group.mu.Unlock()
}
