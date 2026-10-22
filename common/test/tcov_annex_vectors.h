#ifndef LIGHTNING_COMMON_TEST_TCOV_ANNEX_VECTORS_H
#define LIGHTNING_COMMON_TEST_TCOV_ANNEX_VECTORS_H
/* Witnesses of two taproot-covenant spends carrying a BIP341 annex,
 * each mined on a Sequentia chain by generateblock although relay
 * policy refuses it: the peer's offered-SUCCESS claim, whose
 * signature commits to the annex, and a keyless REVOKE claim, whose
 * annex nobody signs. */
#include "config.h"

static const char *V_SUCCESS_ANNEXED[] = {
	"58c69ff638fed95e9edfa075113153337e85ca4b99e8809e841fe726b6aabaa36f4d9c85c4ac81a7c1ac8c09a68da5decc527cb6675373c7cbc8d6772c11044a",
	"579854c902c90fd12ab7ddb95d05ce91fb23c7b8b337354787fedf2120feb964",
	"82012088a914527b339852841e0a32b269aaac3bd284a66b721c8820b2e15fb531f385486d73bdcd575e6b1b51ceea31ea6a8477821d0e11e5d4dafcac",
	"c4fa3c8faddf982098c3f5aea2856f942d98d8c0c16569ff548ddad9a790b0b379301c51b81480d81a72a02115aba7e3cf2de15c6008699aa3a5455581e6c834e8",
	"507365716c6e2d6c34342d616e6e6578",
};
static const char V_SUCCESS_PREIMAGE[] = "579854c902c90fd12ab7ddb95d05ce91fb23c7b8b337354787fedf2120feb964";
static const char *V_REVOKE_ANNEXED[] = {
	"209e5c23b20ca8f65fd9aaa8c23215aa41df0544d5345c9d55592d75617ac175",
	"21037d803650e2f9f55f93b60ede41fb42c33a6cf63775b0e8ab79f24154704ddb2d210279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f817987be3cd76ce518878c851888876cf518878c95188df69d10088146978add7acd4b83dce48682022c0e47ffc8d645187",
	"c5fa3c8faddf982098c3f5aea2856f942d98d8c0c16569ff548ddad9a790b0b379d6cbea826aaf977994fd2bf72d900f4ae1ef1cace2b687da82e83c3e5d07c69d",
	"507365716c6e2d6c34342d616e6e6578",
};

#endif /* LIGHTNING_COMMON_TEST_TCOV_ANNEX_VECTORS_H */
