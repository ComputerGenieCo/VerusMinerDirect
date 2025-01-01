### Install dependencies:  
```
sudo apt-get install libcurl4-openssl-dev libssl-dev libjansson-dev automake autotools-dev build-essential
```  


### Clone and build:
```
git clone https://github.com/ComputerGenieCo/VerusMinerDirect.git && cd VerusMinerDirect/build
./build.sh
```  

### Check packages that may cause build issues:  
```
dpkg -l | grep autoconf
dpkg -l | grep libcurl
```

### Check if dependencies for release are present on system:  
```
ldd VerusMinerDirect
```