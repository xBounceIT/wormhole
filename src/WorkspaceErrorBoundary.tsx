import { Component, type ReactNode } from 'react';

export class WorkspaceErrorBoundary extends Component<{
  children: ReactNode;
  onFailure: () => void;
  onRetry: () => void;
}> {
  state = { failed: false };

  static getDerivedStateFromError() {
    return { failed: true };
  }

  componentDidCatch() {
    this.props.onFailure();
  }

  render() {
    if (!this.state.failed) return this.props.children;
    return (
      <main className="startup-shell">
        <section className="startup-card" role="alert">
          <div className="startup-heading">
            <span>
              <strong>Wormhole couldn't open</strong>
              <small>The workspace encountered an unexpected error. Try reopening it.</small>
            </span>
          </div>
          <button className="startup-button" type="button" onClick={this.props.onRetry}>
            Try again
          </button>
        </section>
      </main>
    );
  }
}
