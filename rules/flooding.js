// Detects transaction flooding patterns:
// - Sender concentration: single address dominating a block
// - Target bombing: many txs aimed at one contract (potential DoS)

(function () {

  // --- Sender Flooding ---------------------------------------------------

  AttackEngine.registerRule({
    id: 'sender-flooding',
    name: 'Sender Flooding',
    severity: 'high',
    category: 'flooding',

    analyze(blockMeta, txs, recentBlocks) {
      if (txs.length < 10) return null;

      const counts = {};
      for (const tx of txs) {
        const from = tx.from.toLowerCase();
        counts[from] = (counts[from] || 0) + 1;
      }

      const top = Object.entries(counts).sort((a, b) => b[1] - a[1])[0];
      if (!top) return null;

      const [addr, count] = top;
      const ratio = count / txs.length;

      if (ratio > 0.1 && count > 5) {
        const flaggedTxHashes = new Set();
        for (const tx of txs) {
          if (tx.from.toLowerCase() === addr) flaggedTxHashes.add(tx.hash);
        }

        let severity = 'low';
        if (ratio > 0.3) severity = 'high';
        else if (ratio > 0.2) severity = 'medium';

        return {
          triggered: true,
          severity,
          summary: count + ' txs from single sender (' + (ratio * 100).toFixed(0) + '%)',
          detail: 'Address ' + addr + ' sent ' + count + ' of ' + txs.length +
            ' transactions in this block. High sender concentration suggests automated tx flooding ' +
            'that can overload RPC endpoints and mempool processing.',
          flaggedTxHashes,
          metrics: { topSender: addr, txCount: count, ratio },
        };
      }
      return null;
    },
  });

  // --- Target Bombing ----------------------------------------------------

  AttackEngine.registerRule({
    id: 'target-bombing',
    name: 'Target Bombing',
    severity: 'high',
    category: 'flooding',

    analyze(blockMeta, txs, recentBlocks) {
      if (txs.length < 10) return null;

      const counts = {};
      for (const tx of txs) {
        if (!tx.to) continue;
        const to = tx.to.toLowerCase();
        counts[to] = (counts[to] || 0) + 1;
      }

      const top = Object.entries(counts).sort((a, b) => b[1] - a[1])[0];
      if (!top) return null;

      const [addr, count] = top;
      const ratio = count / txs.length;

      if (ratio > 0.15 && count > 8) {
        const flaggedTxHashes = new Set();
        for (const tx of txs) {
          if (tx.to && tx.to.toLowerCase() === addr) flaggedTxHashes.add(tx.hash);
        }

        let severity = 'low';
        if (ratio > 0.4) severity = 'high';
        else if (ratio > 0.25) severity = 'medium';

        return {
          triggered: true,
          severity,
          summary: count + ' txs targeting single address (' + (ratio * 100).toFixed(0) + '%)',
          detail: 'Contract ' + addr + ' received ' + count + ' of ' + txs.length +
            ' transactions. Concentrated targeting can exhaust contract gas limits, ' +
            'overload RPC nodes serving call traces, and degrade validator performance.',
          flaggedTxHashes,
          metrics: { topTarget: addr, txCount: count, ratio },
        };
      }
      return null;
    },
  });

})();
