import React, { useMemo } from 'react';

const ScanChart = ({ scans }) => {
  const chartData = useMemo(() => {
    if (!scans || scans.length === 0) return [];
    
    // Group scans by date
    const scansByDate = {};
    scans.forEach((scan) => {
      const date = new Date(scan.created_at).toLocaleDateString(undefined, { 
        month: 'short', 
        day: '2-digit' 
      });
      if (!scansByDate[date]) {
        scansByDate[date] = { total: 0, completed: 0, failed: 0 };
      }
      scansByDate[date].total++;
      const status = scan.status?.toLowerCase();
      if (status === 'completed') {
        scansByDate[date].completed++;
      } else if (status === 'failed') {
        scansByDate[date].failed++;
      }
    });
    
    // Convert to array and sort by date
    return Object.entries(scansByDate)
      .map(([date, data]) => ({ date, ...data }))
      .slice(-7); // Show last 7 days
  }, [scans]);

  if (chartData.length === 0) {
    return (
      <div className="chamfer-panel border border-white/5 bg-[#0d0d0d] p-6">
        <p className="text-[10px] font-bold tracking-[0.35em] text-lambo-gold">// Scan History</p>
        <p className="mt-4 text-sm tracking-[0.22em] text-lambo-ash">No scan data available</p>
      </div>
    );
  }

  const maxTotal = Math.max(...chartData.map(d => d.total), 1);

  return (
    <div className="chamfer-panel border border-white/5 bg-[#0d0d0d] p-6">
      <p className="text-[10px] font-bold tracking-[0.35em] text-lambo-gold">// Scan History (Last 7 Days)</p>
      
      <div className="mt-6 flex items-end gap-2 h-32">
        {chartData.map((data, index) => {
          const height = (data.total / maxTotal) * 100;
          const completedHeight = (data.completed / maxTotal) * 100;
          const failedHeight = (data.failed / maxTotal) * 100;
          
          return (
            <div key={index} className="flex-1 flex flex-col items-center gap-1">
              <div className="w-full flex flex-col justify-end" style={{ height: '100px' }}>
                {/* Failed scans */}
                {failedHeight > 0 && (
                  <div 
                    className="w-full bg-red-500/30 rounded-t"
                    style={{ height: `${failedHeight}%` }}
                  />
                )}
                {/* Completed scans */}
                {completedHeight > 0 && (
                  <div 
                    className="w-full bg-green-500/30"
                    style={{ height: `${completedHeight}%` }}
                  />
                )}
                {/* Pending/running scans */}
                <div 
                  className="w-full bg-lambo-gold/20 rounded-b"
                  style={{ height: `${Math.max(0, height - completedHeight - failedHeight)}%` }}
                />
              </div>
              <span className="text-[9px] sm:text-[10px] tracking-[0.15em] text-lambo-ash">{data.date}</span>
            </div>
          );
        })}
      </div>
      
      <div className="mt-4 flex flex-wrap items-center gap-3 sm:gap-4 text-[9px] sm:text-[10px] tracking-[0.15em]">
        <div className="flex items-center gap-2">
          <div className="h-2 w-2 bg-green-500/30 rounded" />
          <span className="text-lambo-ash">Completed</span>
        </div>
        <div className="flex items-center gap-2">
          <div className="h-2 w-2 bg-red-500/30 rounded" />
          <span className="text-lambo-ash">Failed</span>
        </div>
        <div className="flex items-center gap-2">
          <div className="h-2 w-2 bg-lambo-gold/20 rounded" />
          <span className="text-lambo-ash">Pending</span>
        </div>
      </div>
    </div>
  );
};

export default ScanChart;