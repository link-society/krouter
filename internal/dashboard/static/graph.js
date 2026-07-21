/* Topology flowchart: the only piece of custom JavaScript in the dashboard.

   One GLOBAL dagre layout (left-to-right) assigns the columns, so nodes of
   the same kind stay vertically aligned across namespaces. The vertical
   coordinates are then re-stacked into one disjoint band per namespace, so
   the dashed namespace boxes can never overlap. Edges are uniform cubic
   beziers between box borders. d3 only renders. Redraws after every htmx
   content swap (triggered by the topology server-sent events). */
(function () {
  "use strict";

  var TITLE_HEIGHT = 26;
  var LINE_HEIGHT = 15;
  var PADDING_X = 12;
  var PADDING_BOTTOM = 9;
  var CHAR_WIDTH = 6.8;
  var MIN_WIDTH = 150;
  var MAX_WIDTH = 320;

  var STACK_GAP = 18; /* between stacked nodes of one column in one band */
  var CLUSTER_PAD = 16;
  var CLUSTER_LABEL = 22;
  var CLUSTER_GAP = 40;

  function nodeWidth(node) {
    var longest = node.title.length;

    node.lines.forEach(function (line) {
      if (line.length > longest) {
        longest = line.length;
      }
    });

    var width = longest * CHAR_WIDTH + 2 * PADDING_X;

    return Math.max(MIN_WIDTH, Math.min(MAX_WIDTH, width));
  }

  function nodeHeight(node) {
    return TITLE_HEIGHT + node.lines.length * LINE_HEIGHT + PADDING_BOTTOM;
  }

  async function render() {
    var container = document.getElementById("topology-graph");
    if (!container || typeof d3 === "undefined" || typeof dagre === "undefined") {
      return;
    }

    var response = await fetch("/api/graph", {
      headers: { Accept: "application/json" },
    });
    if (!response.ok) {
      return;
    }

    var graph = await response.json();

    /* ----------------------------------------- global column layout -- */

    var g = new dagre.graphlib.Graph();
    g.setGraph({ rankdir: "LR", nodesep: 28, ranksep: 90, marginx: 0, marginy: 0 });
    g.setDefaultEdgeLabel(function () {
      return {};
    });

    graph.nodes.forEach(function (node) {
      g.setNode(node.id, {
        width: nodeWidth(node),
        height: nodeHeight(node),
      });
    });

    graph.links.forEach(function (link) {
      g.setEdge(link.source, link.target);
    });

    dagre.layout(g);

    /* ------------------------------- restack into namespace bands -- */

    var bands = {};
    var order = [];

    graph.nodes.forEach(function (node) {
      var ns = node.namespace || "(cluster)";

      if (!bands[ns]) {
        bands[ns] = { namespace: ns, nodes: [], minY: Infinity };
        order.push(ns);
      }

      bands[ns].nodes.push(node);

      var y = g.node(node.id).y;
      if (y < bands[ns].minY) {
        bands[ns].minY = y;
      }
    });

    /* Keep the namespaces in the vertical order dagre suggested. */
    order.sort(function (a, z) {
      return bands[a].minY - bands[z].minY;
    });

    var positions = {}; // node id -> {x, y, width, height}
    var offsetY = 0;

    order.forEach(function (ns) {
      var band = bands[ns];

      /* Group the band's nodes by dagre column (same x = same rank). */
      var columns = {};

      band.nodes.forEach(function (node) {
        var x = Math.round(g.node(node.id).x);

        if (!columns[x]) {
          columns[x] = [];
        }

        columns[x].push(node);
      });

      var contentHeight = 0;

      Object.keys(columns).forEach(function (x) {
        /* Preserve dagre's vertical ordering to limit edge crossings. */
        columns[x].sort(function (a, z) {
          return g.node(a.id).y - g.node(z.id).y;
        });

        var height = 0;

        columns[x].forEach(function (node) {
          height += nodeHeight(node) + STACK_GAP;
        });

        contentHeight = Math.max(contentHeight, height - STACK_GAP);
      });

      var top = offsetY + CLUSTER_LABEL + CLUSTER_PAD;

      Object.keys(columns).forEach(function (x) {
        var stack = columns[x];

        var height = 0;
        stack.forEach(function (node) {
          height += nodeHeight(node) + STACK_GAP;
        });
        height -= STACK_GAP;

        /* Center each column stack inside the band. */
        var y = top + (contentHeight - height) / 2;

        stack.forEach(function (node) {
          var h = nodeHeight(node);

          positions[node.id] = {
            x: g.node(node.id).x,
            y: y + h / 2,
            width: nodeWidth(node),
            height: h,
          };

          y += h + STACK_GAP;
        });
      });

      var minX = Infinity;
      var maxX = -Infinity;

      band.nodes.forEach(function (node) {
        var p = positions[node.id];

        minX = Math.min(minX, p.x - p.width / 2);
        maxX = Math.max(maxX, p.x + p.width / 2);
      });

      band.boxX = minX - CLUSTER_PAD;
      band.boxY = offsetY;
      band.boxWidth = maxX - minX + 2 * CLUSTER_PAD;
      band.boxHeight = contentHeight + CLUSTER_LABEL + 2 * CLUSTER_PAD;

      offsetY += band.boxHeight + CLUSTER_GAP;
    });

    var totalHeight = Math.max(offsetY - CLUSTER_GAP, 1);
    var totalWidth = 0;

    order.forEach(function (ns) {
      totalWidth = Math.max(totalWidth, bands[ns].boxX + bands[ns].boxWidth);
    });

    /* ------------------------------------------------------ rendering -- */

    container.replaceChildren();

    var width = container.clientWidth || 960;
    var height = 520;

    var svg = d3
      .select(container)
      .append("svg")
      .attr("viewBox", [0, 0, width, height])
      .attr("width", "100%")
      .attr("height", height);

    var defs = svg.append("defs");

    ["arrow", "arrow-broken"].forEach(function (id) {
      defs
        .append("marker")
        .attr("id", id)
        .attr("viewBox", "0 0 10 10")
        .attr("refX", 9)
        .attr("refY", 5)
        .attr("markerWidth", 7)
        .attr("markerHeight", 7)
        .attr("orient", "auto-start-reverse")
        .append("path")
        .attr("d", "M 0 0 L 10 5 L 0 10 z")
        .attr("class", id);
    });

    var layer = svg.append("g");

    var zoom = d3
      .zoom()
      .scaleExtent([0.2, 3])
      .on("zoom", function (event) {
        layer.attr("transform", event.transform);
      });

    svg.call(zoom);

    /* Namespace boxes. */
    var cluster = layer
      .append("g")
      .selectAll("g")
      .data(order)
      .join("g")
      .attr("class", "graph-cluster");

    cluster
      .append("rect")
      .attr("x", function (ns) {
        return bands[ns].boxX;
      })
      .attr("y", function (ns) {
        return bands[ns].boxY;
      })
      .attr("width", function (ns) {
        return bands[ns].boxWidth;
      })
      .attr("height", function (ns) {
        return bands[ns].boxHeight;
      });

    cluster
      .append("text")
      .attr("x", function (ns) {
        return bands[ns].boxX + 10;
      })
      .attr("y", function (ns) {
        return bands[ns].boxY + CLUSTER_LABEL - 6;
      })
      .text(function (ns) {
        return ns;
      });

    /* Edges: cubic bezier from the source's right edge to the target's
       left edge — identical for intra- and cross-namespace links. */
    function edgePath(link) {
      var s = positions[link.source];
      var t = positions[link.target];

      var sx = s.x + s.width / 2;
      var sy = s.y;
      var tx = t.x - t.width / 2;
      var ty = t.y;
      var mx = (sx + tx) / 2;

      return "M" + sx + "," + sy +
        " C" + mx + "," + sy +
        " " + mx + "," + ty +
        " " + tx + "," + ty;
    }

    layer
      .append("g")
      .selectAll("path")
      .data(graph.links)
      .join("path")
      .attr("d", edgePath)
      .attr("class", function (link) {
        return "graph-edge" + (link.ok ? "" : " is-broken");
      })
      .attr("marker-end", function (link) {
        return link.ok ? "url(#arrow)" : "url(#arrow-broken)";
      });

    /* Nodes. */
    var node = layer
      .append("g")
      .selectAll("g")
      .data(graph.nodes)
      .join("g")
      .attr("class", function (d) {
        return "graph-node kind-" + d.kind + (d.ok ? "" : " is-broken");
      })
      .attr("transform", function (d) {
        var p = positions[d.id];

        return "translate(" + (p.x - p.width / 2) + "," + (p.y - p.height / 2) + ")";
      })
      .on("click", function (event, d) {
        if (d.yamlPath && window.krouterModal) {
          window.krouterModal.open(d.kind + " " + d.title, d.yamlPath);
        }
      });

    node
      .append("rect")
      .attr("class", "graph-box")
      .attr("width", function (d) {
        return positions[d.id].width;
      })
      .attr("height", function (d) {
        return positions[d.id].height;
      });

    node
      .append("rect")
      .attr("class", "graph-accent")
      .attr("width", 4)
      .attr("x", 0)
      .attr("y", 0)
      .attr("height", function (d) {
        return positions[d.id].height;
      });

    node
      .append("text")
      .attr("class", "graph-title")
      .attr("x", PADDING_X)
      .attr("y", 17)
      .text(function (d) {
        return d.title;
      });

    node.each(function (d) {
      var group = d3.select(this);

      d.lines.forEach(function (text, index) {
        group
          .append("text")
          .attr("class", "graph-line")
          .attr("x", PADDING_X)
          .attr("y", TITLE_HEIGHT + 8 + index * LINE_HEIGHT)
          .text(text);
      });
    });

    node.append("title").text(function (d) {
      return d.kind + ": " + d.title + (d.ok ? "" : " (degraded)");
    });

    /* Fit the stacked layout into the viewport. */
    var scale = Math.min(width / (totalWidth + 24), height / (totalHeight + 24), 1);
    var tx = (width - totalWidth * scale) / 2;
    var ty = (height - totalHeight * scale) / 2;

    svg.call(zoom.transform, d3.zoomIdentity.translate(tx, ty).scale(scale));
  }

  document.addEventListener("DOMContentLoaded", render);

  document.body.addEventListener("htmx:afterSwap", function () {
    render();
  });
})();
