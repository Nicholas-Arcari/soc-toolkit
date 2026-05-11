import { useMemo } from "react";
import CytoscapeComponent from "react-cytoscapejs";
import type { StylesheetStyle, LayoutOptions } from "cytoscape";
import type { EntityGraph } from "../../api/client";

/**
 * Generic cytoscape renderer for investigate results.
 *
 * The graph shape is produced server-side so this component stays
 * dumb: it only knows how to turn {nodes, edges} into cytoscape
 * elements and paint them. Any investigate feature that produces an
 * EntityGraph can be visualized here without frontend-side logic.
 */
const NODE_COLOR: Record<string, string> = {
  username: "#14b8a6",
  email: "#f59e0b",
  domain: "#8b5cf6",
  image: "#0ea5e9",
  platform: "#22c55e",
  breach: "#ef4444",
  location: "#ec4899",
  camera: "#64748b",
  software: "#64748b",
  note: "#9ca3af",
};

const stylesheet: StylesheetStyle[] = [
  {
    selector: "node",
    style: {
      label: "data(label)",
      color: "#f3f4f6",
      "font-size": 10,
      "text-wrap": "wrap",
      "text-max-width": "120px",
      "text-valign": "bottom",
      "text-margin-y": 4,
      width: 28,
      height: 28,
      "background-color": "data(color)",
      "border-width": 1,
      "border-color": "#1f2937",
    },
  },
  {
    selector: "edge",
    style: {
      label: "data(label)",
      color: "#9ca3af",
      "font-size": 8,
      width: 1,
      "line-color": "#374151",
      "curve-style": "bezier",
      "target-arrow-shape": "triangle",
      "target-arrow-color": "#374151",
    },
  },
];

const layout: LayoutOptions = {
  name: "cose",
  animate: false,
  fit: true,
  padding: 20,
  nodeRepulsion: () => 8000,
  idealEdgeLength: () => 100,
};

interface Props {
  graph: EntityGraph;
  height?: number;
}

export default function GraphView({ graph, height = 480 }: Props) {
  const elements = useMemo(() => {
    const nodes = graph.nodes.map((n) => ({
      data: {
        id: n.id,
        label: n.label,
        type: n.type,
        color: NODE_COLOR[n.type] ?? "#6b7280",
      },
    }));
    const edges = graph.edges.map((e, i) => ({
      data: {
        id: `e${i}`,
        source: e.source,
        target: e.target,
        label: e.label,
      },
    }));
    return [...nodes, ...edges];
  }, [graph]);

  if (graph.nodes.length === 0) {
    return (
      <div
        className="flex items-center justify-center text-sm text-gray-500 bg-dark-card border border-dark-border rounded-lg"
        style={{ height }}
      >
        No entities to plot.
      </div>
    );
  }

  return (
    <div
      className="bg-dark-card border border-dark-border rounded-lg overflow-hidden"
      style={{ height }}
    >
      <CytoscapeComponent
        elements={elements}
        stylesheet={stylesheet}
        layout={layout}
        style={{ width: "100%", height: "100%" }}
      />
    </div>
  );
}
