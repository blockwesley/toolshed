#Tshark Short Output Script from kristenjacobs container networking repository
#Install tshark with sudo apt-get install tshark

sudo tshark -T fields -e ip.src \
-e ip.dst \
-e frame.protocols \
-E header=y