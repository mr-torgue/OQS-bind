
unsigned get_nr_fragments(const unsigned max_msg_size, const unsigned total_msg_size, const unsigned header_size) {
    return (total_msg_size - (header_size + 4)) / max_msg_size; 
}