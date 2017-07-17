
trafficGen32: trafficGen.cpp
	g++ -m32 -std=c++11 -g -O1 -o trafficGen32 trafficGen.cpp -lpthread -lpcap
	
trafficGen64: trafficGen.cpp
	g++ -m64 -std=c++11 -g -O1 -o trafficGen64 trafficGen.cpp -lpthread -lpcap
	
sender: trafficGen.cpp
	g++ -std=c++11 -g -O1 -D__SENDER -o trafficGen trafficGen.cpp -lpthread -lpcap
	
clean:
	rm -rf *.o trafficGen
