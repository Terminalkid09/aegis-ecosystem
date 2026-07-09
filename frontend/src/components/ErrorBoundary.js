import React from 'react';
import { AlertTriangle } from 'lucide-react';

export default class ErrorBoundary extends React.Component {
  constructor(props) {
    super(props);
    this.state = { hasError: false, error: null };
  }

  static getDerivedStateFromError(error) {
    return { hasError: true, error };
  }

  componentDidCatch(error, errorInfo) {
    console.error('ErrorBoundary caught:', error, errorInfo);
  }

  render() {
    if (this.state.hasError) {
      return (
        <div className="flex flex-col items-center justify-center h-full text-slate-400 p-8">
          <AlertTriangle size={48} className="text-red-500 mb-4" />
          <h3 className="text-lg font-bold mb-2">Something went wrong</h3>
          <p className="text-sm text-slate-500 mb-4 text-center max-w-md">
            {this.props.fallbackMessage || 'An unexpected error occurred while rendering this section.'}
          </p>
          <button
            onClick={() => {
              this.setState({ hasError: false, error: null });
              window.location.reload();
            }}
            className="px-4 py-2 bg-purple-700 hover:bg-purple-600 rounded text-xs font-bold transition-colors"
          >
            Reload page
          </button>
          {process.env.NODE_ENV === 'development' && this.state.error && (
            <pre className="mt-4 text-xs text-red-400 bg-slate-900 p-4 rounded max-w-full overflow-auto">
              {this.state.error.toString()}
            </pre>
          )}
        </div>
      );
    }
    return this.props.children;
  }
}
