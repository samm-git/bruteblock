# Implicit rules
RM=rm -rf

SUFFIXES = .o .c .h .a .so .sl


SRCS = iniparser.c \
	   dictionary.c \
	   strlib.c

OBJS = $(SRCS:.c=.o)


default:	libiniparser.a

libiniparser.a:	$(OBJS)
	@($(AR) $(ARFLAGS) libiniparser.a $(OBJS))

clean:
	$(RM) $(OBJS) libiniparser.a
