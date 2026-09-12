using System;
using System.Collections.Generic;
using System.Globalization;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Input;
using System.Windows.Media;
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
            Background = new SolidColorBrush(Color.FromRgb(6, 9, 16)); // #060910

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

            // Central Target Node: example.com
            var center = new VisualNode
            {
                Id = "center",
                Label = "example.com",
                Subtitle = "192.168.1.10",
                NodeType = "center",
                Status = "active",
                X = 270,
                Y = 155,
                ColorHex = "#00F0FF"
            };
            _nodes.Add(center);

            // Left Subdomains
            var subdomains = new[]
            {
                ("sub-1", "mail.example.com", 115.0, 65.0, "#00F0FF"),
                ("sub-2", "dev.example.com", 95.0, 125.0, "#00F0FF"),
                ("sub-3", "api.example.com", 105.0, 190.0, "#10B981"),
                ("sub-4", "staging.example.com", 125.0, 250.0, "#3B82F6")
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

            // Right Port Services
            var ports = new[]
            {
                ("port-80", "Port 80", "HTTP", 415.0, 65.0, "#10B981"),
                ("port-443", "Port 443", "HTTPS", 425.0, 115.0, "#00F0FF"),
                ("port-22", "Port 22", "SSH", 425.0, 170.0, "#F59E0B"),
                ("port-3306", "Port 3306", "MySQL", 415.0, 225.0, "#EF4444"),
                ("port-6379", "Port 6379", "Redis", 395.0, 275.0, "#F59E0B")
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

            // Draw Cyber Grid Dots Background
            var gridPen = new Pen(new SolidColorBrush(Color.FromArgb(25, 0, 240, 255)), 1);
            var dotBrush = new SolidColorBrush(Color.FromArgb(35, 148, 163, 184));
            for (double gx = 15; gx < ActualWidth; gx += 30)
            {
                for (double gy = 15; gy < ActualHeight; gy += 30)
                {
                    dc.DrawEllipse(dotBrush, null, new Point(gx, gy), 1, 1);
                }
            }

            // Save transform state
            dc.PushTransform(new TranslateTransform(_panOffset.X, _panOffset.Y));
            dc.PushTransform(new ScaleTransform(_zoom, _zoom));

            // 1. Draw glowing connecting Bézier curves
            foreach (var edge in _edges)
            {
                var src = _nodes.Find(n => n.Id == edge.SourceId);
                var tgt = _nodes.Find(n => n.Id == edge.TargetId);
                if (src == null || tgt == null) continue;

                var p1 = new Point(src.X, src.Y);
                var p2 = new Point(tgt.X, tgt.Y);
                var midX = (p1.X + p2.X) / 2;

                var col = (Color)ColorConverter.ConvertFromString(edge.ColorHex);

                // Outer soft glow line
                var glowPen = new Pen(new SolidColorBrush(Color.FromArgb(40, col.R, col.G, col.B)), 3.5);
                var pen = new Pen(new SolidColorBrush(Color.FromArgb(140, col.R, col.G, col.B)), 1.5)
                {
                    DashStyle = new DashStyle(new double[] { 3, 2 }, 0)
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

                dc.DrawGeometry(null, glowPen, geo);
                dc.DrawGeometry(null, pen, geo);

                // Draw tiny data packet dot on mid point
                var midY = (p1.Y + p2.Y) / 2;
                dc.DrawEllipse(new SolidColorBrush(col), null, new Point(midX, midY), 2.2, 2.2);
            }

            // 2. Draw Nodes
            foreach (var node in _nodes)
            {
                var col = (Color)ColorConverter.ConvertFromString(node.ColorHex);
                var brush = new SolidColorBrush(col);
                var darkCard = new SolidColorBrush(Color.FromRgb(11, 16, 28)); // #0B101C
                var borderPen = new Pen(brush, 1.8);

                if (node.NodeType == "center")
                {
                    // Central Target Node with multiple radiant rings
                    var r = 26.0;

                    // Radiant outer pulse rings
                    dc.DrawEllipse(null, new Pen(new SolidColorBrush(Color.FromArgb(30, col.R, col.G, col.B)), 8), new Point(node.X, node.Y), r + 8, r + 8);
                    dc.DrawEllipse(null, new Pen(new SolidColorBrush(Color.FromArgb(70, col.R, col.G, col.B)), 2), new Point(node.X, node.Y), r + 4, r + 4);
                    dc.DrawEllipse(darkCard, borderPen, new Point(node.X, node.Y), r, r);

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

                    // Label badge below center
                    var labelText = new FormattedText(
                        node.Label,
                        CultureInfo.InvariantCulture,
                        FlowDirection.LeftToRight,
                        new Typeface(new FontFamily("Segoe UI Variable Display, Consolas"), FontStyles.Normal, FontWeights.Bold, FontStretches.Normal),
                        11,
                        new SolidColorBrush(Color.FromRgb(240, 246, 255)),
                        1.0
                    );
                    dc.DrawText(labelText, new Point(node.X - labelText.Width / 2, node.Y + r + 5));
                }
                else if (node.NodeType == "subdomain")
                {
                    var r = 16.0;
                    // Outer subtle halo
                    dc.DrawEllipse(null, new Pen(new SolidColorBrush(Color.FromArgb(40, col.R, col.G, col.B)), 4), new Point(node.X, node.Y), r + 2, r + 2);
                    dc.DrawEllipse(darkCard, borderPen, new Point(node.X, node.Y), r, r);

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

                    // Label text on the left
                    var labelText = new FormattedText(
                        node.Label,
                        CultureInfo.InvariantCulture,
                        FlowDirection.LeftToRight,
                        new Typeface(new FontFamily("Segoe UI Variable Display, Segoe UI"), FontStyles.Normal, FontWeights.SemiBold, FontStretches.Normal),
                        9.5,
                        new SolidColorBrush(Color.FromRgb(203, 213, 225)),
                        1.0
                    );
                    dc.DrawText(labelText, new Point(node.X - labelText.Width - 22, node.Y - labelText.Height / 2));
                }
                else if (node.NodeType == "port")
                {
                    var r = 16.0;
                    // Outer subtle halo
                    dc.DrawEllipse(null, new Pen(new SolidColorBrush(Color.FromArgb(40, col.R, col.G, col.B)), 4), new Point(node.X, node.Y), r + 2, r + 2);
                    dc.DrawEllipse(darkCard, borderPen, new Point(node.X, node.Y), r, r);

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

                    // Text to right: Port name & service
                    var portText = new FormattedText(
                        node.Label,
                        CultureInfo.InvariantCulture,
                        FlowDirection.LeftToRight,
                        new Typeface(new FontFamily("Segoe UI Variable Display, Segoe UI"), FontStyles.Normal, FontWeights.Bold, FontStretches.Normal),
                        10,
                        new SolidColorBrush(Color.FromRgb(248, 250, 252)),
                        1.0
                    );
                    var svcText = new FormattedText(
                        node.Subtitle,
                        CultureInfo.InvariantCulture,
                        FlowDirection.LeftToRight,
                        new Typeface(new FontFamily("Consolas"), FontStyles.Normal, FontWeights.Normal, FontStretches.Normal),
                        8.5,
                        new SolidColorBrush(Color.FromRgb(148, 163, 184)),
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
