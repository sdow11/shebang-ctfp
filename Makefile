PY = python3
TARGET = reflector

.PHONY: run
run: $(TARGET)

$(TARGET): $(TARGET).py
	chmod +x $(TARGET).py
	cp $(TARGET).py $(TARGET)

.PHONY: clean
clean: 
	rm reflector
