# netfilter-test Makefile

CXX = g++
CXXFLAGS = -std=c++11 -Wall -I./NetworkHeader
LDFLAGS = -lnetfilter_queue

TARGET = netfilter-test
SRCS = netfilter-test.cpp NetworkHeader/addr_cast.cpp NetworkHeader/arp.cpp NetworkHeader/ethernet.cpp NetworkHeader/ipv4.cpp NetworkHeader/tcp.cpp

all: $(TARGET)

$(TARGET): $(SRCS)
	$(CXX) $(CXXFLAGS) -o $@ $^ $(LDFLAGS)

clean:
	rm -f $(TARGET)

.PHONY: all clean