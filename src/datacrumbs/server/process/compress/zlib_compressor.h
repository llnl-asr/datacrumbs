// SPDX-License-Identifier: MIT
// Owner: hariharandev1@llnl.gov

#pragma once
// Generated Headers
#include <datacrumbs/datacrumbs_config.h>
// Other headers
#include <datacrumbs/common/logging.h>
// std headers
#include <zlib.h>

#include <cstdint>
#include <stdexcept>
#include <string>
#include <vector>

namespace datacrumbs {

/**
 * @brief Buffered gzip compressor for streaming trace output.
 */
class ZlibCompression {
 public:
  /**
   * @brief Create gzip compressor bound to output file.
   * @param output_file Destination gzip file path.
   * @param chunk_size Buffer chunk size for batched writes.
   * @throws std::runtime_error on file open or zlib init failure.
   */
  ZlibCompression(const std::string& output_file, size_t chunk_size)
      : output_file_(output_file), chunk_size_(chunk_size), buffer_(chunk_size) {
    file_ = std::fopen(output_file_.c_str(), "wb");
    if (!file_) {
      throw std::runtime_error("Failed to open output file for writing");
    }
    strm_.zalloc = Z_NULL;
    strm_.zfree = Z_NULL;
    strm_.opaque = Z_NULL;
    if (deflateInit2(&strm_, Z_DEFAULT_COMPRESSION, Z_DEFLATED, 15 + 16, 8, Z_DEFAULT_STRATEGY) !=
        Z_OK) {
      std::fclose(file_);
      throw std::runtime_error("Failed to initialize zlib for gzip compression");
    }
    buffer_offset_ = 0;
  }

  ~ZlibCompression() {}

  /**
   * @brief Finalize stream, flush remaining bytes, and close output file.
   */
  void finalize() {
    DC_LOG_DEBUG("Finalizing compression");
    flush();
    deflateEnd(&strm_);
    if (file_) {
      DC_LOG_DEBUG("Closing output file");
      std::fclose(file_);
    }
    DC_LOG_DEBUG("Compression finalized");
  }

  /**
   * @brief Compress one data chunk into output stream.
   * @param data Plain-text payload chunk.
   * @throws std::runtime_error on zlib compression failure.
   */
  void compress(const std::string& data) {
    DC_LOG_DEBUG("Compressing data of size: %zu bytes", data.size());
    strm_.avail_in = static_cast<uInt>(data.size());
    strm_.next_in = reinterpret_cast<Bytef*>(const_cast<char*>(data.data()));

    while (strm_.avail_in > 0) {
      strm_.avail_out = static_cast<uInt>(chunk_size_ - buffer_offset_);
      strm_.next_out = reinterpret_cast<Bytef*>(&buffer_[buffer_offset_]);
      int ret = deflate(&strm_, Z_NO_FLUSH);
      if (ret != Z_OK && ret != Z_STREAM_END) {
        throw std::runtime_error("Compression failed");
      }
      size_t have = chunk_size_ - buffer_offset_ - strm_.avail_out;
      buffer_offset_ += have;
      if (buffer_offset_ == chunk_size_) {
        write_chunk();
      }
    }
  }

  /**
   * @brief Flush pending compressed bytes and finish zlib stream.
   */
  void flush() {
    int ret;
    do {
      DC_LOG_DEBUG("Flushing compression buffer");
      strm_.avail_out = static_cast<uInt>(chunk_size_ - buffer_offset_);
      strm_.next_out = reinterpret_cast<Bytef*>(&buffer_[buffer_offset_]);
      ret = deflate(&strm_, Z_FINISH);
      size_t have = chunk_size_ - buffer_offset_ - strm_.avail_out;
      buffer_offset_ += have;
      if (buffer_offset_ == chunk_size_) {
        write_chunk();
      }
    } while (ret != Z_STREAM_END);

    if (buffer_offset_ > 0) {
      write_chunk();
    }
  }

 private:
  /// Write current compressed buffer to file.
  void write_chunk() {
    if (buffer_offset_ > 0 && file_) {
      if (std::fwrite(buffer_.data(), 1, buffer_offset_, file_) != buffer_offset_) {
        perror("Failed to write compressed chunk to file");
      }
      fflush(file_);
      DC_LOG_DEBUG("Wrote compressed chunk of size: %zu bytes", buffer_offset_);
      buffer_offset_ = 0;
    }
  }

  /// Output gzip file path.
  std::string output_file_;
  /// Compression chunk size.
  size_t chunk_size_;
  /// Intermediate compressed data buffer.
  std::vector<uint8_t> buffer_;
  /// Current write offset into buffer_.
  size_t buffer_offset_;
  /// Output file handle.
  FILE* file_;
  /// zlib deflate stream state.
  z_stream strm_;
};
}  // namespace datacrumbs