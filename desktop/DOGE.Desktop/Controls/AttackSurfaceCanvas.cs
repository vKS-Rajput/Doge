using System;
using System.Collections.Generic;
using System.Globalization;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Input;
using System.Windows.Media;
using System.Windows.Media.Effects;
using DOGE.Desktop.Models;

namespace DOGE.Desktop.Controls
{
    public class AttackSurfaceCanvas : Canvas
    {
        private readonly List<VisualNode> _nodes = new();
        private readonly List<VisualEdge> _edges = new();

        private double _zoom = 1.0;
        private Point _panOffset = new(0, 0);
        private Point _lastMousePos;
        private bool _isPanning = false;

        public event Action<VisualNode>? NodeSelected;

        public AttackSurfaceCanvas()
        {
            ClipToBounds = true;
            Background = new SolidColorBrush(Color.FromRgb(7, 10, 17)); // #070A11

            InitializeDefaultGraph();

            MouseLeftButtonDown += OnMouseDown;
            MouseLeftButtonUp += OnMouseUp;
            MouseMove += OnMouseMove;
            MouseWheel += OnMouseWheel;
        }

        public void InitializeDefaultGraph()
        {
            _nodes.Clear();
            _edges.Clear();

            // Center Node: example.com
            var center = new VisualNode
            {
                Id = "center",
                Label = "example.com",
                Subtitle = "192.168.1.10",
                NodeType = "center",
                Status = "active",
                X = 260,
                Y = 160,
                ColorHex = "#00F0FF"
            };
            _nodes.Add(center);

            // Left Subdomains
            var subdomains = new[]
            {
                ("sub-1", "mail.example.com", 120.0, 70.0, "#00F0FF"),
                ("sub-2", "dev.example.com", 100.0, 130.0, "#00F0FF"),
                ("sub-3", "api.example.com", 110.0, 195.0, "#10B981"),
                ("sub-4", "staging.example.com", 130.0, 255.0, "#3B82F6")
            };

            foreach (var (id, label, x, y, col) in subdomains)
            {
                var n = new VisualNode
                {
                    Id = id,
                    Label = label,
                    NodeType = "subdomain",
                    Status = "discovered",
                    X = x,
                    Y = y,
                    ColorHex = col
                };
                _nodes.Add(n);
                _edges.Add(new VisualEdge { SourceId = center.Id, TargetId = id, ColorHex = col });
            }

            // Right Ports
            var ports = new[]
            {
                ("port-80", "Port 80", "HTTP", 390.0, 70.0, "#10B981"),
                ("port-443", "Port 443", "HTTPS", 400.0, 120.0, "#00F0FF"),
                ("port-22", "Port 22", "SSH", 400.0, 175.0, "#F59E0B"),
                ("port-3306", "Port 3306", "MySQL", 390.0, 230.0, "#EF4444"),
                ("port-6379", "Port 6379", "Redis", 370.0, 280.0, "#F59E0B")
            };

            foreach (var (id, label, sub, x, y, col) in ports)
            {
                var n = new VisualNode
                {
                    Id = id,
                    Label = label,
                    Subtitle = sub,
                    NodeType = "port",
                    Status = "service",
                    X = x,
                    Y = y,
                    ColorHex = col
                };
                _nodes.Add(n);
                _edges.Add(new VisualEdge { SourceId = center.Id, TargetId = id, ColorHex = col });
            }

            InvalidateVisual();
        }

        public void ZoomIn()
        {
            _zoom = Math.Min(2.5, _zoom + 0.15);
            InvalidateVisual();
        }

        public void ZoomOut()
        {
            _zoom = Math.Max(0.5, _zoom - 0.15);
            InvalidateVisual();
        }

        public void ResetView()
        {
            _zoom = 1.0;
            _panOffset = new Point(0, 0);
            InvalidateVisual();
        }

        protected override void OnRender(DrawingContext dc)
        {
            base.OnRender(dc);

            // Save transform state
            dc.PushTransform(new TranslateTransform(_panOffset.X, _panOffset.Y));
            dc.PushTransform(new ScaleTransform(_zoom, _zoom));

            // 1. Draw connecting Bézier curves
            foreach (var edge in _edges)
            {
                var src = _nodes.Find(n => n.Id == edge.SourceId);
                var tgt = _nodes.Find(n => n.Id == edge.TargetId);
                if (src == null || tgt == null) continue;

                var p1 = new Point(src.X, src.Y);
                var p2 = new Point(tgt.X, tgt.Y);
                var midX = (p1.X + p2.X) / 2;

                var col = (Color)ColorConverter.ConvertFromString(edge.ColorHex);
                var pen = new Pen(new SolidColorBrush(Color.FromArgb(110, col.R, col.G, col.B)), 1.5)
                {
                    DashStyle = DashStyles.Dash
                };

                var figure = new PathFigure { StartPoint = p1 };
                figure.Segments.Add(new BezierSegment(
                    new Point(midX, p1.Y),
                    new Point(midX, p2.Y),
                    p2,
                    true
                ));

                var geo = new PathGeometry();
                geo.Figures.Add(figure);
                dc.DrawGeometry(null, pen, geo);
            }

            // 2. Draw Nodes
            foreach (var node in _nodes)
            {
                var col = (Color)ColorConverter.ConvertFromString(node.ColorHex);
                var brush = new SolidColorBrush(col);
                var darkBg = new SolidColorBrush(Color.FromRgb(14, 20, 36)); // #0E1424
                var borderPen = new Pen(brush, 1.8);

                if (node.NodeType == "center")
                {
                    // Large center globe node
                    var r = 26.0;
                    // Outer glow ring
                    dc.DrawEllipse(null, new Pen(new SolidColorBrush(Color.FromArgb(60, col.R, col.G, col.B)), 6), new Point(node.X, node.Y), r + 4, r + 4);
                    dc.DrawEllipse(darkBg, borderPen, new Point(node.X, node.Y), r, r);

                    // Central icon symbol
                    var iconText = new FormattedText(
                        "🌐",
                        CultureInfo.InvariantCulture,
                        FlowDirection.LeftToRight,
                        new Typeface("Segoe UI Emoji"),
                        18,
                        brush,
                        1.0
                    );
                    dc.DrawText(iconText, new Point(node.X - iconText.Width / 2, node.Y - iconText.Height / 2));

                    // Label below center
                    var labelText = new FormattedText(
                        node.Label,
                        CultureInfo.InvariantCulture,
                        FlowDirection.LeftToRight,
                        new Typeface("Consolas, Segoe UI"),
                        11,
                        new SolidColorBrush(Color.FromRgb(220, 240, 255)),
                        1.0
                    );
                    dc.DrawText(labelText, new Point(node.X - labelText.Width / 2, node.Y + r + 4));
                }
                else if (node.NodeType == "subdomain")
                {
                    // Subdomain node: rounded box with computer/chip icon
                    var r = 16.0;
                    dc.DrawEllipse(darkBg, borderPen, new Point(node.X, node.Y), r, r);

                    var iconText = new FormattedText(
                        node.Id.Contains("api") ? "⚡" : "🖥",
                        CultureInfo.InvariantCulture,
                        FlowDirection.LeftToRight,
                        new Typeface("Segoe UI Emoji"),
                        13,
                        brush,
                        1.0
                    );
                    dc.DrawText(iconText, new Point(node.X - iconText.Width / 2, node.Y - iconText.Height / 2));

                    // Label text on the left/right
                    var labelText = new FormattedText(
                        node.Label,
                        CultureInfo.InvariantCulture,
                        FlowDirection.LeftToRight,
                        new Typeface("Consolas, Segoe UI"),
                        9.5,
                        new SolidColorBrush(Color.FromRgb(180, 200, 220)),
                        1.0
                    );
                    dc.DrawText(labelText, new Point(node.X - labelText.Width - 20, node.Y - labelText.Height / 2));
                }
                else if (node.NodeType == "port")
                {
                    // Port node on right: circular badge with port name and service
                    var r = 16.0;
                    dc.DrawEllipse(darkBg, borderPen, new Point(node.X, node.Y), r, r);

                    var iconText = new FormattedText(
                        "🔌",
                        CultureInfo.InvariantCulture,
                        FlowDirection.LeftToRight,
                        new Typeface("Segoe UI Emoji"),
                        11,
                        brush,
                        1.0
                    );
                    dc.DrawText(iconText, new Point(node.X - iconText.Width / 2, node.Y - iconText.Height / 2));

                    // Text to right: "Port 80" + "HTTP"
                    var portText = new FormattedText(
                        node.Label,
                        CultureInfo.InvariantCulture,
                        FlowDirection.LeftToRight,
                        new Typeface("Segoe UI"),
                        10,
                        new SolidColorBrush(Color.FromRgb(240, 246, 255)),
                        1.0
                    );
                    var svcText = new FormattedText(
                        node.Subtitle,
                        CultureInfo.InvariantCulture,
                        FlowDirection.LeftToRight,
                        new Typeface("Consolas"),
                        8.5,
                        new SolidColorBrush(Color.FromRgb(130, 150, 180)),
                        1.0
                    );

                    dc.DrawText(portText, new Point(node.X + r + 8, node.Y - 11));
                    dc.DrawText(svcText, new Point(node.X + r + 8, node.Y + 2));
                }
            }

            // Pop scale and translate transforms
            dc.Pop();
            dc.Pop();
        }

        private void OnMouseDown(object sender, MouseButtonEventArgs e)
        {
            if (e.ChangedButton == MouseButton.Left)
            {
                _isPanning = true;
                _lastMousePos = e.GetPosition(this);
                CaptureMouse();

                // Check node hit
                var clickPos = e.GetPosition(this);
                var transformed = new Point(
                    (clickPos.X - _panOffset.X) / _zoom,
                    (clickPos.Y - _panOffset.Y) / _zoom
                );

                foreach (var node in _nodes)
                {
                    var dist = Math.Sqrt(Math.Pow(transformed.X - node.X, 2) + Math.Pow(transformed.Y - node.Y, 2));
                    if (dist <= 25)
                    {
                        NodeSelected?.Invoke(node);
                        break;
                    }
                }
            }
        }

        private void OnMouseUp(object sender, MouseButtonEventArgs e)
        {
            if (_isPanning)
            {
                _isPanning = false;
                ReleaseMouseCapture();
            }
        }

        private void OnMouseMove(object sender, MouseEventArgs e)
        {
            if (_isPanning)
            {
                var currentPos = e.GetPosition(this);
                _panOffset.X += currentPos.X - _lastMousePos.X;
                _panOffset.Y += currentPos.Y - _lastMousePos.Y;
                _lastMousePos = currentPos;
                InvalidateVisual();
            }
        }

        private void OnMouseWheel(object sender, MouseWheelEventArgs e)
        {
            if (e.Delta > 0)
                ZoomIn();
            else
                ZoomOut();
        }
    }
}
