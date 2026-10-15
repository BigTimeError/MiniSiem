import {
  ResponsiveContainer,
  LineChart,
  Line,
  XAxis,
  YAxis,
  CartesianGrid,
  Tooltip,
} from "recharts";

import type {
  TimeInterval,
} from "../types/siem";

interface ChartData {
  timestamp: string;
  events: number;
  alerts: number;
}

interface EventsOverTimeChartProps {
  data: ChartData[];
  interval: TimeInterval;
  onIntervalChange: (interval: TimeInterval) => void;
}

function EventsOverTimeChart({
  data,
  interval,
  onIntervalChange,
}: EventsOverTimeChartProps) {
  const chartData = data.map((bucket) => {
    const date = new Date(bucket.timestamp);

    let time: string;

    if (interval === "hour") {
      time = date.toLocaleTimeString([], {
        hour: "2-digit",
        minute: "2-digit",
      });
    } else {
      time = date.toLocaleDateString([], {
        day: "2-digit",
        month: "2-digit",
      });
    }

    return {
      ...bucket,
      time,
    };
  });

  return (
    <section className="content-card" style={{ padding: "20px" }}>
      <div
        className="section-header"
        style={{ padding: 0, marginBottom: "20px", borderBottom: "none" }}
      >
        <div>
          <h2 style={{ fontSize: "16px", margin: 0 }}>
            Events & Alerts over time
          </h2>

          <p style={{ margin: "4px 0 0", fontSize: "12px", color: "var(--text-muted)" }}>
            {interval === "hour" &&
              "Events and alerts detected during the last 24 hours"}

            {interval === "day" &&
              "Events and alerts detected during the last 7 days"}

            {interval === "week" &&
              "Events and alerts detected during the last 4 weeks"}
          </p>
        </div>

        <select
          className="filter-select"
          value={interval}
          onChange={(event) =>
            onIntervalChange(
              event.target.value as TimeInterval,
            )
          }
          style={{ width: "auto", padding: "4px 8px", fontSize: "12px" }}
        >
          <option value="hour">24H</option>
          <option value="day">7D</option>
          <option value="week">4W</option>
        </select>
      </div>

      <div style={{ width: "100%", height: "280px" }}>
        <ResponsiveContainer width="100%" height="100%">
          <LineChart
            data={chartData}
            margin={{
              top: 10,
              right: 10,
              left: -20,
              bottom: 0,
            }}
          >
            <CartesianGrid
              strokeDasharray="3 3"
              stroke="var(--border-subtle, #262b36)"
            />

            <XAxis
              dataKey="time"
              tick={{
                fill: "#8b93a1",
                fontSize: 12,
              }}
              axisLine={{
                stroke: "var(--border-subtle, #262b36)",
              }}
              tickLine={false}
            />

            <YAxis
              allowDecimals={false}
              tick={{
                fill: "#8b93a1",
                fontSize: 12,
              }}
              axisLine={false}
              tickLine={false}
            />

            <Tooltip
              contentStyle={{
                backgroundColor: "var(--bg-card, #151821)",
                border: "1px solid var(--border-subtle, #262b36)",
                borderRadius: "6px",
                color: "var(--text-primary, #e5e7eb)",
              }}
              labelStyle={{
                color: "#8b93a1",
              }}
              formatter={(value, name) => [
                value,
                name === "events"
                  ? "Events"
                  : "Alerts",
              ]}
            />

            <Line
              type="monotone"
              dataKey="events"
              stroke="#60a5fa"
              strokeWidth={2}
              dot={false}
              activeDot={{
                r: 4,
              }}
            />

            <Line
              type="monotone"
              dataKey="alerts"
              stroke="#f87171"
              strokeWidth={2}
              dot={false}
              activeDot={{
                r: 4,
              }}
            />
          </LineChart>
        </ResponsiveContainer>
      </div>
    </section>
  );
}

export default EventsOverTimeChart;