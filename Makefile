CXX      := g++
CXXFLAGS := -std=c++17 -Wall -Wextra -Wpedantic -O2 \
           -fstack-protector-strong -D_FORTIFY_SOURCE=2 -fPIE
LDFLAGS  := -pthread -pie -Wl,-z,relro,-z,now

SRCDIR   := src
SOURCES  := $(wildcard $(SRCDIR)/*.cpp)
OBJECTS  := $(SOURCES:.cpp=.o)
TARGET   := slaacbot

.PHONY: all clean install

all: $(TARGET)

$(TARGET): $(OBJECTS)
	$(CXX) $(CXXFLAGS) -o $@ $^ $(LDFLAGS)

$(SRCDIR)/%.o: $(SRCDIR)/%.cpp
	$(CXX) $(CXXFLAGS) -c -o $@ $<

clean:
	rm -f $(OBJECTS) $(TARGET)

install: $(TARGET)
	install -m 755 $(TARGET) /usr/local/sbin/$(TARGET)
	install -m 644 slaacbot.service /etc/systemd/system/slaacbot.service
	@echo "Copied slaacbot to /usr/local/sbin and slaacbot.service to /etc/systemd/system/."
	@echo "Run: systemctl daemon-reload && systemctl enable --now slaacbot.service"
	@echo "Copy config.ini to /etc/slaacbot.conf and edit as needed."
