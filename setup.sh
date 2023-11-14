#!/bin/sh

# install python3 venv

echo "Initializing virtualenv..."
python3 -m venv venv
source ./venv/bin/activate
echo "Setup venv succeed"

echo "installing python3 dependencies..."
pip install -r requirements.txt
echo "All dependencies have been installed"

echo "Installing welpwn..."
if [ -f "welpwn" ]; then
    git clone https://github.com/matrix1001/welpwn && cd welpwn && python setup.py install
fi
echo "Welpwn have been installed"

echo "Creating flag file..."
echo "flag{some_text_here}" > flag.txt

echo "Completed!"
