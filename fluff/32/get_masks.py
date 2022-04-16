def get_masks(src, dest):
    """Constructs mask for pext assembly instrution, see:
    https://www.felixcloutier.com/x86/pext

    :param src: Source integer value (e.g 0xb0bababa).
    :param dest: String to obtain after pext operation (e.g "flag.txt").
    :return: N masks, where N is equal to the number of bytes in dest,
        each mask is an integer value.
    """
    src = bin(src)[2:]
    src = src[::-1]
    dests = [bin(x)[2:] for x in bytearray(dest, "ascii")]
    masks = []

    for dest in dests:
        dest = dest[::-1]
        mask = []

        i_dest = 0
        i_src = 0

        while True:
            if src[i_src] == dest[i_dest]:
                mask.append(1)
                i_src += 1
                i_dest += 1
            else:
                mask.append(0)
                i_src += 1

            if i_dest == len(dest):
                break
            elif i_src == len(src):
                raise ValueError("Can't craft the mask!")

        mask = mask[::-1]
        mask = "".join(str(x) for x in mask)
        mask = int(mask, 2)
        masks.append(mask)

    return masks
