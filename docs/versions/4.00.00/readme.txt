This major release introduced a significant change to the sub-protocol for RISP.

Both protocols use the highest bit in 16-bit command ID to indicate whether to take the integer value that follows as a length of the 
amount of binary data that follows.  Ie, is the parameter an integer, or an integer which is the length of the string that follows?  
This has not changed.

What has changed however, is the handling of the size indicator of the Integer that follows.

In the previous protocol, it used the next high 4 bits to provide a literal length of the Integer that follows.

0000 - 0 bytes.
0001 - 1 bytes (8-bit)
0010 - 2 bytes (16-bit)
0011 - 3 bytes
0100 - 4 bytes (32-bit)
0101 - 5 bytes
0110 - 6 bytes
0111 - 7 bytes
1000 - 8 bytes (64-bit)
1001 - 9 bytes
1010 - 10 bytes
1011 - 11 bytes
1100 - 12 bytes
1101 - 13 bytes
1110 - 14 bytes
1111 - 15 bytes

As can be seen here, there are a large number of ranges that would never be used, because they are for very non-standard integer ranges.

If we present the same list but just with the standard integer sizes, we see a pattern.

0000 - 0 bytes.
0001 - 1 bytes (8-bit)
0010 - 2 bytes (16-bit)
0100 - 4 bytes (32-bit)
1000 - 8 bytes (64-bit)

We can se that a single bit is moving around.  We can therefore store how many times to shift that bit to the left, and we can store it 
in 3 bits instead of 4.

This does add a complication in how to indicate that no parameter follows the command.  Our encoding scheme doesn't naturally cater for 
it, so we have to put some special rules in.  Note that this particular complication was my original reasoning for abandoning this idea.  
I have since decided the advantages outweigh the disadvantages.

In order to cater for non-parameter commands, we will instead use some particular cases that are not going to be used for anything 
meaningful, and use logic to indicate that no parameters follow for those particular ranges.

Therefore;

Command Style Ranges
// 1 byte integer - 0x0000 to 0x0fff         0 000 xxxx xxxx
// 2 byte integer - 0x1000 to 0x1fff         0 001 xxxx xxxx    
// 4 byte integer - 0x2000 to 0x2fff         0 010 xxxx xxxx
// 8 byte integer - 0x3000 to 0x3fff         0 011 xxxx xxxx
// 16 byte integer - 0x4000 to 0x4fff        0 100 xxxx xxxx
// 32 byte integer - 0x5000 to 0x5fff        0 101 xxxx xxxx
// 64 byte integer - 0x6000 to 0x6fff        0 110 xxxx xxxx
// No Parameters - 0x7000 to 0x7fff          0 111 xxxx xxxx
// 1 byte-length string - 0x8000 to 0x8fff   1 000 xxxx xxxx
// 2 byte-length string - 0x9000 to 0x9fff   1 001 xxxx xxxx
// 4 byte-length string - 0xa000 to 0xafff   1 010 xxxx xxxx
// 8 byte-length string - 0xb000 to 0xbfff   1 011 xxxx xxxx
// No Parameters - 0xc000 to 0xffff          1 1xx xxxx xxxx
