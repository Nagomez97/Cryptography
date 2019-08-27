JFLAGS = -g
JC = javac -cp ../bouncycastle.jar
.SUFFIXES: .java .class
.java.class:
	$(JC) $(JFLAGS) $*.java

CLASSES = \
        ChaCha20encrypt.java \
        ChaCha20decrypt.java

default: classes

classes: $(CLASSES:.java=.class)

clean:
	$(RM) *.class
