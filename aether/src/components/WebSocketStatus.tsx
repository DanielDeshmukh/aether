interface WebSocketStatusProps {
  isConnected: boolean;
  isReconnecting: boolean;
  onRetry?: () => void;
}

export default function WebSocketStatus({ isConnected, isReconnecting, onRetry }: WebSocketStatusProps) {
  if (isConnected) return null;

  return (
    <div className="fixed bottom-4 right-4 z-50">
      <div className="chamfer-panel border border-yellow-500/30 bg-yellow-500/10 px-4 py-3 shadow-lg backdrop-blur-sm">
        <div className="flex items-center gap-3">
          <div className={`h-2 w-2 rounded-full ${isReconnecting ? "animate-pulse bg-yellow-400" : "bg-red-400"}`} />
          <span className="text-[10px] font-bold tracking-[0.2em] text-yellow-400">
            {isReconnecting ? "RECONNECTING..." : "CONNECTION LOST"}
          </span>
          {!isReconnecting && onRetry && (
            <button onClick={onRetry} className="chamfer-button border border-yellow-500/30 bg-yellow-500/20 px-3 py-2 text-[9px] sm:text-[10px] font-bold tracking-[0.15em] text-yellow-400 hover:bg-yellow-500/30 transition-colors">
              RETRY
            </button>
          )}
        </div>
      </div>
    </div>
  );
}
