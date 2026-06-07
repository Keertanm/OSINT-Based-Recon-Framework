#!/bin/bash
cd "$(dirname "$0")/spiderfoot"
echo "🚀 Starting SpiderFoot..."
python3 sf.py -l 127.0.0.1:5001
