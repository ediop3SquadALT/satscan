# satscan
A satellite scanner. Finds vulnerable satellites (very hard to find) and saves the non vulnerable satellites into satellite_log.txt


Linux installation (Kali, parrot, debian)
```
sudo apt update && sudo apt upgrade -y

sudo apt install python3 python3-pip git -y

pip3 install requests beautifulsoup4

git clone https://github.com/ediop3SquadALT/satscan

cd satscan
chmod +x satscan.sh
./satscan.sh
```


termux installation

```
apt update && apt upgrade -y

apt install python3 python3-pip git -y

pip install requests beautifulsoup4

git clone https://github.com/ediop3SquadALT/satscan

cd satscan
chmod +x satscan.sh
./satscan.sh
```
