import { Component, type ReactNode } from 'react';
import { AlertTriangle, RotateCw } from 'lucide-react';

// Keeps one broken page from blanking the whole console.
export default class ErrorBoundary extends Component<{ children: ReactNode; resetKey?: string }, { error: Error | null }> {
  state = { error: null as Error | null };

  static getDerivedStateFromError(error: Error) {
    return { error };
  }

  componentDidUpdate(prev: { resetKey?: string }) {
    if (prev.resetKey !== this.props.resetKey && this.state.error) this.setState({ error: null });
  }

  render() {
    if (!this.state.error) return this.props.children;
    return (
      <div className="max-w-xl mx-auto mt-16 text-center space-y-4 bg-slate-900/60 border border-rose-900/60 rounded-2xl p-8">
        <AlertTriangle className="w-8 h-8 text-rose-400 mx-auto" />
        <h2 className="text-lg font-bold text-white">This page hit a snag</h2>
        <p className="text-sm text-slate-400">The rest of CowSec is fine. Pick another page, or reload this one.</p>
        <p className="text-xs font-mono text-rose-300/80 break-all">{this.state.error.message}</p>
        <button onClick={() => window.location.reload()} className="inline-flex items-center gap-2 rounded-xl px-4 py-2 text-sm font-semibold text-white bg-slate-700 hover:bg-slate-600 cursor-pointer">
          <RotateCw className="w-4 h-4" /> Reload
        </button>
      </div>
    );
  }
}
