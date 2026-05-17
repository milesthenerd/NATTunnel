using System.Threading.Tasks;
using Avalonia.Controls;
using Avalonia.Layout;
using Avalonia.Media;

namespace NATTunnelGUI;

/// <summary>Tiny stand-ins for WPF's MessageBox — Avalonia doesn't ship one.</summary>
internal static class DialogHelpers
{
    public static Task ShowInfoAsync(Window owner, string title, string message)
        => ShowAsync(owner, title, message, new[] { "OK" });

    public static async Task<bool> ShowYesNoAsync(Window owner, string title, string message)
    {
        string result = await ShowAsync(owner, title, message, new[] { "No", "Yes" });
        return result == "Yes";
    }

    private static Task<string> ShowAsync(Window owner, string title, string message, string[] buttons)
    {
        var tcs = new TaskCompletionSource<string>();

        var stack = new StackPanel { Margin = new Avalonia.Thickness(20), Spacing = 16 };
        stack.Children.Add(new TextBlock
        {
            Text = message,
            TextWrapping = TextWrapping.Wrap,
        });

        var buttonPanel = new StackPanel
        {
            Orientation = Orientation.Horizontal,
            HorizontalAlignment = HorizontalAlignment.Right,
            Spacing = 8,
        };

        var dialog = new Window
        {
            Title = title,
            Width = 360,
            SizeToContent = SizeToContent.Height,
            WindowStartupLocation = WindowStartupLocation.CenterOwner,
            CanResize = false,
            Content = stack,
        };

        foreach (var label in buttons)
        {
            var btn = new Button
            {
                Content = label,
                MinWidth = 70,
                HorizontalContentAlignment = HorizontalAlignment.Center,
            };
            btn.Click += (_, _) =>
            {
                tcs.TrySetResult(label);
                dialog.Close();
            };
            buttonPanel.Children.Add(btn);
        }
        stack.Children.Add(buttonPanel);

        dialog.Closed += (_, _) => tcs.TrySetResult("");
        dialog.ShowDialog(owner);
        return tcs.Task;
    }
}
