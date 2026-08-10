// Detects gas-related anomalies:
// - Base fee spikes relative to rolling average
// - Priority fee outliers (MEV bidding wars, sandwich attacks)

(function () {

  // --- Base Fee Spike ----------------------------------------------------

  AttackEngine.registerRule({
    id: 'base-fee-spike',
    name: 'Base Fee Spike',
    severity: 'medium',
    category: 'gas',

    analyze(blockMeta, txs, recentBlocks) {
      if (recentBlocks.length < 3) return null;
      if (blockMeta.baseFeeWei === 0) return null;

      const avg = recentBlocks.reduce((s, b) => s + b.baseFeeWei, 0) / recentBlocks.length;
      if (avg === 0) return null;

      const ratio = blockMeta.baseFeeWei / avg;

      if (ratio > 2) {
        let severity = 'low';
        if (ratio > 5) severity = 'critical';
        else if (ratio > 3) severity = 'high';
        else severity = 'medium';

        const curGwei = (blockMeta.baseFeeWei / 1e9).toFixed(3);
        const avgGwei = (avg / 1e9).toFixed(3);

        return {
          triggered: true,
          severity,
          summary: 'Base fee ' + ratio.toFixed(1) + 'x above average (' + curGwei + ' gwei)',
          detail: 'Current base fee is ' + curGwei + ' gwei vs ' + avgGwei +
            ' gwei rolling average. Rapid base fee increases signal sustained full blocks, ' +
            'often caused by flooding attacks that consume all available block space ' +
            'and force legitimate users to overpay.',
          flaggedTxHashes: null,
          metrics: { ratio, currentGwei: curGwei, avgGwei },
        };
      }
      return null;
    },
  });

  // --- Priority Fee Anomaly ----------------------------------------------

  AttackEngine.registerRule({
    id: 'priority-fee-anomaly',
    name: 'Priority Fee Anomaly',
    severity: 'medium',
    category: 'gas',

    analyze(blockMeta, txs, recentBlocks) {
      if (txs.length < 5) return null;

      const tips = txs.map(tx => {
        const gasPrice = tx.gasPrice ? parseInt(tx.gasPrice, 16) : 0;
        return Math.max(0, gasPrice - blockMeta.baseFeeWei);
      }).sort((a, b) => a - b);

      const median = tips[Math.floor(tips.length / 2)];
      if (median === 0) return null;

      const maxTip = tips[tips.length - 1];
      const ratio = maxTip / median;

      const outliers = tips.filter(t => t > median * 10);

      if (ratio > 10 && outliers.length >= 2) {
        const threshold = median * 10;
        const flaggedTxHashes = new Set();
        for (const tx of txs) {
          const gasPrice = tx.gasPrice ? parseInt(tx.gasPrice, 16) : 0;
          const tip = Math.max(0, gasPrice - blockMeta.baseFeeWei);
          if (tip > threshold) flaggedTxHashes.add(tx.hash);
        }

        let severity = 'low';
        if (ratio > 100) severity = 'high';
        else if (ratio > 50) severity = 'medium';

        return {
          triggered: true,
          severity,
          summary: outliers.length + ' txs with ' + ratio.toFixed(0) + 'x outlier tips',
          detail: outliers.length + ' transactions are tipping ' + ratio.toFixed(0) +
            'x above median (' + (median / 1e9).toFixed(4) + ' gwei). Extreme tip variance ' +
            'may indicate MEV bidding wars, sandwich attacks, or priority auction manipulation ' +
            'where bots compete to front-run or back-run victim transactions.',
          flaggedTxHashes,
          metrics: { maxTipRatio: ratio, outlierCount: outliers.length, medianGwei: median / 1e9 },
        };
      }
      return null;
    },
  });

})();
