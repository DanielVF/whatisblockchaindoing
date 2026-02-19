// Detects block capacity anomalies:
// - Block stuffing: near-full blocks consuming all gas
// - Empty blocks: abnormally low tx counts suggesting node issues

(function () {

  // --- Block Stuffing ----------------------------------------------------

  AttackEngine.registerRule({
    id: 'block-stuffing',
    name: 'Block Stuffing',
    severity: 'high',
    category: 'capacity',

    analyze(blockMeta, txs, recentBlocks) {
      if (blockMeta.gasLimit === 0) return null;

      const utilization = blockMeta.gasUsed / blockMeta.gasLimit;

      if (utilization > 0.95) {
        const recentFull = recentBlocks.filter(
          b => b.gasLimit > 0 && (b.gasUsed / b.gasLimit) > 0.95
        ).length;

        let severity = 'low';
        if (utilization > 0.99 && recentFull >= 3) severity = 'critical';
        else if (utilization > 0.99) severity = 'high';
        else if (recentFull >= 2) severity = 'medium';

        return {
          triggered: true,
          severity,
          summary: 'Block ' + (utilization * 100).toFixed(1) + '% full' +
            (recentFull > 0 ? ' (' + recentFull + ' recent full blocks)' : ''),
          detail: 'Gas utilization at ' + (utilization * 100).toFixed(1) + '% of limit. ' +
            (recentFull > 0
              ? recentFull + ' of last ' + recentBlocks.length + ' blocks also >95% full. '
              : '') +
            'Sustained full blocks indicate block stuffing attacks designed to manipulate ' +
            'the base fee, deny block space to other users, or stress-test node block processing.',
          flaggedTxHashes: null,
          metrics: { utilization, recentFullCount: recentFull },
        };
      }
      return null;
    },
  });

  // --- Empty Block Anomaly -----------------------------------------------

  AttackEngine.registerRule({
    id: 'empty-blocks',
    name: 'Empty Block Anomaly',
    severity: 'medium',
    category: 'capacity',

    analyze(blockMeta, txs, recentBlocks) {
      if (recentBlocks.length < 3) return null;

      const avg = recentBlocks.reduce((s, b) => s + b.txCount, 0) / recentBlocks.length;

      if (avg > 10 && txs.length < avg * 0.1) {
        let severity = 'low';
        if (txs.length === 0) severity = 'medium';

        const recentEmpty = recentBlocks.slice(-3).filter(b => b.txCount < avg * 0.1).length;
        if (recentEmpty >= 2) severity = 'high';

        return {
          triggered: true,
          severity,
          summary: 'Block has ' + txs.length + ' txs (avg ' + Math.round(avg) + ')',
          detail: 'Unusually empty block with ' + txs.length + ' transactions vs average of ' +
            Math.round(avg) + '. May indicate node isolation, validator issues, network ' +
            'partitioning, or mempool exhaustion from a prior flooding attack.',
          flaggedTxHashes: null,
          metrics: { txCount: txs.length, avgTxCount: avg },
        };
      }
      return null;
    },
  });

})();
