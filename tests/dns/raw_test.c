// unit tests
test_raw_get_nr_fragments() {
    // test case 1: normal case
    // test case 2: just enough space
    // test case 3: 1 byte in new fragment
    // test case 4: large fixed size (leave 10 bytes for dynamic data)
    // test case 5: too much static data 
}

test_raw_create_opt() {
    // test case 1: normal case
    // test case 2: no existing OPT record
    // test case 3: nr fragments < fragment nr
}

test_raw_get_sizes_offsets() {
    // test case 1: normal, cut-off point
    // test case 2: no cut-off last RR
    // test case 3: last RR covers 4 fragments

}

test_raw_create_fragment_response() {
    // test case 1: normal case
    // test case 2: no OPT record
    // test case 3: no Question
    // test case 4: different normal case
}

test_raw_fragment() {
    // test case 1: normal case
    // test case 2: normal case, different cipher (hybrid)

}

test_raw_reassemble_fragments() {
    // test case 1: normal case
}