JFLAGS = -g
JC = javac -cp ../bouncycastle.jar
.SUFFIXES: .java .class
.java.class:
	$(JC) $(JFLAGS) $*.java

CLASSES = \
        CAMELLIAencrypt.java \
        CAMELLIAdecrypt.java

default: classes

classes: $(CLASSES:.java=.class)

clean:
	$(RM) *.class
