using System;
using System.Diagnostics;
using System.IO;
using System.Text;
using System.Windows.Controls;
using System.Windows.Threading;

namespace NATTunnelGUI;

/// <summary>
/// Redirects Console.Out/Console.Error to a WPF TextBox on the UI thread.
/// </summary>
public class GuiTextWriter : TextWriter
{
    private readonly TextBox textBox;
    private readonly Dispatcher dispatcher;
    private const int MaxLines = 1000;

    public GuiTextWriter(TextBox textBox)
    {
        this.textBox = textBox;
        dispatcher = textBox.Dispatcher;
    }

    public override Encoding Encoding => Encoding.UTF8;

    public override void Write(char value)
    {
        Append(value.ToString());
    }

    public override void Write(string value)
    {
        if (value != null)
            Append(value);
    }

    public override void WriteLine(string value)
    {
        Append((value ?? "") + Environment.NewLine);
    }

    private void Append(string text)
    {
        Debug.Write(text);

        dispatcher.BeginInvoke(() =>
        {
            textBox.AppendText(text);

            // Cap line count to prevent memory growth
            if (textBox.LineCount > MaxLines)
            {
                int removeUpTo = textBox.GetCharacterIndexFromLineIndex(textBox.LineCount - MaxLines);
                textBox.Text = textBox.Text[removeUpTo..];
            }

            textBox.ScrollToEnd();
        });
    }
}
