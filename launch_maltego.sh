#!/bin/bash

OS="$(uname -s)"

case "$OS" in
    Darwin)
        MALTEGO="/Applications/Maltego.app/Contents/MacOS/Maltego"
        if [ -f "$MALTEGO" ]; then
            echo "🚀 Launching Maltego on macOS..."
            "$MALTEGO" --nosplash -J-Djava.security.manager=allow
        else
            echo "[-] Maltego not found at $MALTEGO"
            echo "    Download from: https://www.maltego.com/downloads/"
        fi
        ;;
    Linux)
        if command -v maltego &> /dev/null; then
            echo "🚀 Launching Maltego on Linux..."
            maltego --nosplash
        else
            echo "[-] Maltego not found in PATH"
            echo "    Download from: https://www.maltego.com/downloads/"
        fi
        ;;
    MINGW*|CYGWIN*|MSYS*)
        MALTEGO="C:/Program Files/Maltego/maltego.exe"
        if [ -f "$MALTEGO" ]; then
            echo "🚀 Launching Maltego on Windows..."
            "$MALTEGO"
        else
            echo "[-] Maltego not found at $MALTEGO"
            echo "    Download from: https://www.maltego.com/downloads/"
        fi
        ;;
    *)
        echo "[-] Unsupported OS: $OS"
        echo "    Download Maltego from: https://www.maltego.com/downloads/"
        ;;
esac
