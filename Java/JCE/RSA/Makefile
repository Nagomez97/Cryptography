JFLAGS = -g
JC = javac
.SUFFIXES: .java .class
.java.class:
		$(JC) $(JFLAGS) $*.java

CLASSES = \
		RSAencrypt.java \
		RSAdecrypt.java \
		RSAkeygen.java

default: classes

classes: $(CLASSES:.java=.class)

clean:
		$(RM) *.class *.pem *.key *.der
