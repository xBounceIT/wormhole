// An SSH shell and its SFTP subsystems hold the same native VPN lease. Duplicate
// close/error notifications must not release it before the last tab is gone.
export class SharedSshRoutes {
  private readonly owners = new Map<string, string>();
  private readonly groups = new Map<string, Set<string>>();

  attach(sourceId: string, sessionId: string): void {
    const owner = this.owners.get(sourceId) ?? sourceId;
    const members = this.groups.get(owner) ?? new Set([sourceId]);
    members.add(sessionId);
    this.groups.set(owner, members);
    this.owners.set(sourceId, owner);
    this.owners.set(sessionId, owner);
  }

  clear(): void {
    this.owners.clear();
    this.groups.clear();
  }

  release(sessionId: string): string | undefined {
    const owner = this.owners.get(sessionId);
    if (!owner) return sessionId;
    const members = this.groups.get(owner)!;
    members.delete(sessionId);
    if (members.size) return undefined;
    this.groups.delete(owner);
    for (const [member, routeOwner] of this.owners) {
      if (routeOwner === owner) this.owners.delete(member);
    }
    return owner;
  }
}
