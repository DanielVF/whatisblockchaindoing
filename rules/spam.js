// Detects spam patterns:
// - Zero-value spam: empty-payload tx flooding
// - Contract creation bursts: factory-pattern state bloat
// - Selector flooding: coordinated calls to one function
// - Calldata bloat: oversized payloads degrading propagation

(function () {

  // --- Zero-Value Spam ---------------------------------------------------

  AttackEngine.registerRule({
    id: 'zero-value-spam',
    name: 'Zero-Value Spam',
    severity: 'medium',
    category: 'spam',

    analyze(blockMeta, txs, recentBlocks) {
      if (txs.length < 10) return null;

      const spam = txs.filter(tx => {
        const value = BigInt(tx.value);
        const inputLen = tx.input ? (tx.input.length - 2) / 2 : 0;
        return value === 0n && inputLen < 100;
      });

      const ratio = spam.length / txs.length;

      if (ratio > 0.5 && spam.length > 20) {
        let severity = 'low';
        if (ratio > 0.8) severity = 'high';
        else if (ratio > 0.6) severity = 'medium';

        return {
          triggered: true,
          severity,
          summary: spam.length + ' zero-value txs (' + (ratio * 100).toFixed(0) + '%)',
          detail: spam.length + ' of ' + txs.length +
            ' transactions carry zero value with minimal calldata (<100 bytes). ' +
            'Empty-payload flooding congests the mempool, inflates RPC response sizes, ' +
            'and wastes validator compute on economically meaningless transactions.',
          flaggedTxHashes: new Set(spam.map(tx => tx.hash)),
          metrics: { count: spam.length, ratio },
        };
      }
      return null;
    },
  });

  // --- Contract Creation Burst -------------------------------------------

  AttackEngine.registerRule({
    id: 'contract-creation-burst',
    name: 'Contract Creation Burst',
    severity: 'medium',
    category: 'spam',

    analyze(blockMeta, txs, recentBlocks) {
      if (txs.length < 5) return null;

      const creations = txs.filter(tx => !tx.to);
      const ratio = creations.length / txs.length;

      if (ratio > 0.2 && creations.length > 5) {
        let severity = 'low';
        if (ratio > 0.5) severity = 'high';
        else if (ratio > 0.3) severity = 'medium';

        return {
          triggered: true,
          severity,
          summary: creations.length + ' contract deployments (' + (ratio * 100).toFixed(0) + '%)',
          detail: creations.length + ' contract creation transactions in a single block. ' +
            'Factory-pattern flooding bloats state storage, increases node sync costs, ' +
            'degrades RPC performance for eth_getCode/eth_call, and can exhaust ' +
            'node disk I/O during state trie updates.',
          flaggedTxHashes: new Set(creations.map(tx => tx.hash)),
          metrics: { count: creations.length, ratio },
        };
      }
      return null;
    },
  });

  // --- Selector Flooding -------------------------------------------------

  var COMMON_SELECTORS = new Set([
    '0xa9059cbb', // transfer
    '0x23b872dd', // transferFrom
    '0x095ea7b3', // approve
    '0x',         // no data
  ]);

  AttackEngine.registerRule({
    id: 'selector-flooding',
    name: 'Selector Flooding',
    severity: 'medium',
    category: 'spam',

    analyze(blockMeta, txs, recentBlocks) {
      if (txs.length < 10) return null;

      var counts = {};
      for (var i = 0; i < txs.length; i++) {
        var tx = txs[i];
        var sel = tx.input && tx.input.length >= 10
          ? tx.input.slice(0, 10).toLowerCase() : '0x';
        if (COMMON_SELECTORS.has(sel)) continue;
        counts[sel] = (counts[sel] || 0) + 1;
      }

      var top = Object.entries(counts).sort(function (a, b) { return b[1] - a[1]; })[0];
      if (!top) return null;

      var sel = top[0], count = top[1];
      var ratio = count / txs.length;

      if (ratio > 0.4 && count > 15) {
        var flaggedTxHashes = new Set();
        for (var j = 0; j < txs.length; j++) {
          var txSel = txs[j].input && txs[j].input.length >= 10
            ? txs[j].input.slice(0, 10).toLowerCase() : '0x';
          if (txSel === sel) flaggedTxHashes.add(txs[j].hash);
        }

        var severity = 'low';
        if (ratio > 0.7) severity = 'high';
        else if (ratio > 0.5) severity = 'medium';

        return {
          triggered: true,
          severity,
          summary: count + ' txs calling ' + sel + ' (' + (ratio * 100).toFixed(0) + '%)',
          detail: 'Function selector ' + sel + ' appears in ' + count + ' of ' + txs.length +
            ' transactions (excluding common ERC-20 methods). Coordinated calls to ' +
            'the same endpoint may indicate automated flooding of a contract, potentially ' +
            'overloading node eth_call tracing and state access.',
          flaggedTxHashes: flaggedTxHashes,
          metrics: { selector: sel, count: count, ratio: ratio },
        };
      }
      return null;
    },
  });

  // --- Calldata Bloat ----------------------------------------------------

  AttackEngine.registerRule({
    id: 'calldata-bloat',
    name: 'Calldata Bloat',
    severity: 'medium',
    category: 'spam',

    analyze(blockMeta, txs, recentBlocks) {
      if (txs.length < 5) return null;

      var sizes = txs.map(function (tx) {
        return tx.input ? (tx.input.length - 2) / 2 : 0;
      });
      var avg = sizes.reduce(function (s, v) { return s + v; }, 0) / sizes.length;
      var large = [];
      for (var i = 0; i < txs.length; i++) {
        if (sizes[i] > 10000) large.push(txs[i]);
      }

      if (avg > 5000 || large.length > txs.length * 0.2) {
        var severity = 'low';
        if (avg > 20000) severity = 'high';
        else if (avg > 10000 || large.length > txs.length * 0.3) severity = 'medium';

        return {
          triggered: true,
          severity,
          summary: 'Avg calldata ' + (avg / 1000).toFixed(1) + 'KB, ' + large.length + ' large txs',
          detail: 'Average calldata size is ' + (avg / 1000).toFixed(1) + 'KB with ' +
            large.length + ' transactions over 10KB. Large calldata flooding increases ' +
            'block propagation time across the P2P network, strains RPC nodes serving ' +
            'eth_getBlockByNumber, and can degrade overall network throughput.',
          flaggedTxHashes: new Set(large.map(function (tx) { return tx.hash; })),
          metrics: { avgSizeKB: avg / 1000, largeTxCount: large.length },
        };
      }
      return null;
    },
  });

})();
