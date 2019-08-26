JFLAGS = -g
JC = javac -cp ../bouncycastle.jar
.SUFFIXES: .java .class
.java.class:
	$(JC) $(JFLAGS) $*.java

CLASSES = \
        AES-GCMencrypt.java \
        AES-GCMdecrypt.java

default: classes

classes: $(CLASSES:.java=.class)

clean:
	$(RM) *.class
