// Generated by the protocol buffer compiler.  DO NOT EDIT!
// source: protobuf_se.proto

#include "protobuf_se.pb.h"

#include <algorithm>

#include <google/protobuf/stubs/common.h>
#include <google/protobuf/stubs/port.h>
#include <google/protobuf/io/coded_stream.h>
#include <google/protobuf/wire_format_lite_inl.h>
#include <google/protobuf/descriptor.h>
#include <google/protobuf/generated_message_reflection.h>
#include <google/protobuf/reflection_ops.h>
#include <google/protobuf/wire_format.h>
// This is a temporary google only hack
#ifdef GOOGLE_PROTOBUF_ENFORCE_UNIQUENESS
#include "third_party/protobuf/version.h"
#endif
// @@protoc_insertion_point(includes)

namespace grpc_se {
class GrpcMsgTXDefaultTypeInternal {
 public:
  ::google::protobuf::internal::ExplicitlyConstructed<GrpcMsgTX>
      _instance;
} _GrpcMsgTX_default_instance_;
class NothingDefaultTypeInternal {
 public:
  ::google::protobuf::internal::ExplicitlyConstructed<Nothing>
      _instance;
} _Nothing_default_instance_;
}  // namespace grpc_se
namespace protobuf_protobuf_5fse_2eproto {
static void InitDefaultsGrpcMsgTX() {
  GOOGLE_PROTOBUF_VERIFY_VERSION;

  {
    void* ptr = &::grpc_se::_GrpcMsgTX_default_instance_;
    new (ptr) ::grpc_se::GrpcMsgTX();
    ::google::protobuf::internal::OnShutdownDestroyMessage(ptr);
  }
  ::grpc_se::GrpcMsgTX::InitAsDefaultInstance();
}

::google::protobuf::internal::SCCInfo<0> scc_info_GrpcMsgTX =
    {{ATOMIC_VAR_INIT(::google::protobuf::internal::SCCInfoBase::kUninitialized), 0, InitDefaultsGrpcMsgTX}, {}};

static void InitDefaultsNothing() {
  GOOGLE_PROTOBUF_VERIFY_VERSION;

  {
    void* ptr = &::grpc_se::_Nothing_default_instance_;
    new (ptr) ::grpc_se::Nothing();
    ::google::protobuf::internal::OnShutdownDestroyMessage(ptr);
  }
  ::grpc_se::Nothing::InitAsDefaultInstance();
}

::google::protobuf::internal::SCCInfo<0> scc_info_Nothing =
    {{ATOMIC_VAR_INIT(::google::protobuf::internal::SCCInfoBase::kUninitialized), 0, InitDefaultsNothing}, {}};

void InitDefaults() {
  ::google::protobuf::internal::InitSCC(&scc_info_GrpcMsgTX.base);
  ::google::protobuf::internal::InitSCC(&scc_info_Nothing.base);
}

::google::protobuf::Metadata file_level_metadata[2];

const ::google::protobuf::uint32 TableStruct::offsets[] GOOGLE_PROTOBUF_ATTRIBUTE_SECTION_VARIABLE(protodesc_cold) = {
  ~0u,  // no _has_bits_
  GOOGLE_PROTOBUF_GENERATED_MESSAGE_FIELD_OFFSET(::grpc_se::GrpcMsgTX, _internal_metadata_),
  ~0u,  // no _extensions_
  ~0u,  // no _oneof_case_
  ~0u,  // no _weak_field_map_
  GOOGLE_PROTOBUF_GENERATED_MESSAGE_FIELD_OFFSET(::grpc_se::GrpcMsgTX, message_),
  ~0u,  // no _has_bits_
  GOOGLE_PROTOBUF_GENERATED_MESSAGE_FIELD_OFFSET(::grpc_se::Nothing, _internal_metadata_),
  ~0u,  // no _extensions_
  ~0u,  // no _oneof_case_
  ~0u,  // no _weak_field_map_
};
static const ::google::protobuf::internal::MigrationSchema schemas[] GOOGLE_PROTOBUF_ATTRIBUTE_SECTION_VARIABLE(protodesc_cold) = {
  { 0, -1, sizeof(::grpc_se::GrpcMsgTX)},
  { 6, -1, sizeof(::grpc_se::Nothing)},
};

static ::google::protobuf::Message const * const file_default_instances[] = {
  reinterpret_cast<const ::google::protobuf::Message*>(&::grpc_se::_GrpcMsgTX_default_instance_),
  reinterpret_cast<const ::google::protobuf::Message*>(&::grpc_se::_Nothing_default_instance_),
};

void protobuf_AssignDescriptors() {
  AddDescriptors();
  AssignDescriptors(
      "protobuf_se.proto", schemas, file_default_instances, TableStruct::offsets,
      file_level_metadata, NULL, NULL);
}

void protobuf_AssignDescriptorsOnce() {
  static ::google::protobuf::internal::once_flag once;
  ::google::protobuf::internal::call_once(once, protobuf_AssignDescriptors);
}

void protobuf_RegisterTypes(const ::std::string&) GOOGLE_PROTOBUF_ATTRIBUTE_COLD;
void protobuf_RegisterTypes(const ::std::string&) {
  protobuf_AssignDescriptorsOnce();
  ::google::protobuf::internal::RegisterAllTypes(file_level_metadata, 2);
}

void AddDescriptorsImpl() {
  InitDefaults();
  static const char descriptor[] GOOGLE_PROTOBUF_ATTRIBUTE_SECTION_VARIABLE(protodesc_cold) = {
      "\n\021protobuf_se.proto\022\007grpc_se\"\034\n\tGrpcMsgT"
      "X\022\017\n\007message\030\001 \001(\014\"\t\n\007Nothing2G\n\016GruutSe"
      "Service\0225\n\013transaction\022\022.grpc_se.GrpcMsg"
      "TX\032\020.grpc_se.Nothing\"\000b\006proto3"
  };
  ::google::protobuf::DescriptorPool::InternalAddGeneratedFile(
      descriptor, 150);
  ::google::protobuf::MessageFactory::InternalRegisterGeneratedFile(
    "protobuf_se.proto", &protobuf_RegisterTypes);
}

void AddDescriptors() {
  static ::google::protobuf::internal::once_flag once;
  ::google::protobuf::internal::call_once(once, AddDescriptorsImpl);
}
// Force AddDescriptors() to be called at dynamic initialization time.
struct StaticDescriptorInitializer {
  StaticDescriptorInitializer() {
    AddDescriptors();
  }
} static_descriptor_initializer;
}  // namespace protobuf_protobuf_5fse_2eproto
namespace grpc_se {

// ===================================================================

void GrpcMsgTX::InitAsDefaultInstance() {
}
#if !defined(_MSC_VER) || _MSC_VER >= 1900
const int GrpcMsgTX::kMessageFieldNumber;
#endif  // !defined(_MSC_VER) || _MSC_VER >= 1900

GrpcMsgTX::GrpcMsgTX()
  : ::google::protobuf::Message(), _internal_metadata_(NULL) {
  ::google::protobuf::internal::InitSCC(
      &protobuf_protobuf_5fse_2eproto::scc_info_GrpcMsgTX.base);
  SharedCtor();
  // @@protoc_insertion_point(constructor:grpc_se.GrpcMsgTX)
}
GrpcMsgTX::GrpcMsgTX(const GrpcMsgTX& from)
  : ::google::protobuf::Message(),
      _internal_metadata_(NULL) {
  _internal_metadata_.MergeFrom(from._internal_metadata_);
  message_.UnsafeSetDefault(&::google::protobuf::internal::GetEmptyStringAlreadyInited());
  if (from.message().size() > 0) {
    message_.AssignWithDefault(&::google::protobuf::internal::GetEmptyStringAlreadyInited(), from.message_);
  }
  // @@protoc_insertion_point(copy_constructor:grpc_se.GrpcMsgTX)
}

void GrpcMsgTX::SharedCtor() {
  message_.UnsafeSetDefault(&::google::protobuf::internal::GetEmptyStringAlreadyInited());
}

GrpcMsgTX::~GrpcMsgTX() {
  // @@protoc_insertion_point(destructor:grpc_se.GrpcMsgTX)
  SharedDtor();
}

void GrpcMsgTX::SharedDtor() {
  message_.DestroyNoArena(&::google::protobuf::internal::GetEmptyStringAlreadyInited());
}

void GrpcMsgTX::SetCachedSize(int size) const {
  _cached_size_.Set(size);
}
const ::google::protobuf::Descriptor* GrpcMsgTX::descriptor() {
  ::protobuf_protobuf_5fse_2eproto::protobuf_AssignDescriptorsOnce();
  return ::protobuf_protobuf_5fse_2eproto::file_level_metadata[kIndexInFileMessages].descriptor;
}

const GrpcMsgTX& GrpcMsgTX::default_instance() {
  ::google::protobuf::internal::InitSCC(&protobuf_protobuf_5fse_2eproto::scc_info_GrpcMsgTX.base);
  return *internal_default_instance();
}


void GrpcMsgTX::Clear() {
// @@protoc_insertion_point(message_clear_start:grpc_se.GrpcMsgTX)
  ::google::protobuf::uint32 cached_has_bits = 0;
  // Prevent compiler warnings about cached_has_bits being unused
  (void) cached_has_bits;

  message_.ClearToEmptyNoArena(&::google::protobuf::internal::GetEmptyStringAlreadyInited());
  _internal_metadata_.Clear();
}

bool GrpcMsgTX::MergePartialFromCodedStream(
    ::google::protobuf::io::CodedInputStream* input) {
#define DO_(EXPRESSION) if (!GOOGLE_PREDICT_TRUE(EXPRESSION)) goto failure
  ::google::protobuf::uint32 tag;
  // @@protoc_insertion_point(parse_start:grpc_se.GrpcMsgTX)
  for (;;) {
    ::std::pair<::google::protobuf::uint32, bool> p = input->ReadTagWithCutoffNoLastTag(127u);
    tag = p.first;
    if (!p.second) goto handle_unusual;
    switch (::google::protobuf::internal::WireFormatLite::GetTagFieldNumber(tag)) {
      // bytes message = 1;
      case 1: {
        if (static_cast< ::google::protobuf::uint8>(tag) ==
            static_cast< ::google::protobuf::uint8>(10u /* 10 & 0xFF */)) {
          DO_(::google::protobuf::internal::WireFormatLite::ReadBytes(
                input, this->mutable_message()));
        } else {
          goto handle_unusual;
        }
        break;
      }

      default: {
      handle_unusual:
        if (tag == 0) {
          goto success;
        }
        DO_(::google::protobuf::internal::WireFormat::SkipField(
              input, tag, _internal_metadata_.mutable_unknown_fields()));
        break;
      }
    }
  }
success:
  // @@protoc_insertion_point(parse_success:grpc_se.GrpcMsgTX)
  return true;
failure:
  // @@protoc_insertion_point(parse_failure:grpc_se.GrpcMsgTX)
  return false;
#undef DO_
}

void GrpcMsgTX::SerializeWithCachedSizes(
    ::google::protobuf::io::CodedOutputStream* output) const {
  // @@protoc_insertion_point(serialize_start:grpc_se.GrpcMsgTX)
  ::google::protobuf::uint32 cached_has_bits = 0;
  (void) cached_has_bits;

  // bytes message = 1;
  if (this->message().size() > 0) {
    ::google::protobuf::internal::WireFormatLite::WriteBytesMaybeAliased(
      1, this->message(), output);
  }

  if ((_internal_metadata_.have_unknown_fields() &&  ::google::protobuf::internal::GetProto3PreserveUnknownsDefault())) {
    ::google::protobuf::internal::WireFormat::SerializeUnknownFields(
        (::google::protobuf::internal::GetProto3PreserveUnknownsDefault()   ? _internal_metadata_.unknown_fields()   : _internal_metadata_.default_instance()), output);
  }
  // @@protoc_insertion_point(serialize_end:grpc_se.GrpcMsgTX)
}

::google::protobuf::uint8* GrpcMsgTX::InternalSerializeWithCachedSizesToArray(
    bool deterministic, ::google::protobuf::uint8* target) const {
  (void)deterministic; // Unused
  // @@protoc_insertion_point(serialize_to_array_start:grpc_se.GrpcMsgTX)
  ::google::protobuf::uint32 cached_has_bits = 0;
  (void) cached_has_bits;

  // bytes message = 1;
  if (this->message().size() > 0) {
    target =
      ::google::protobuf::internal::WireFormatLite::WriteBytesToArray(
        1, this->message(), target);
  }

  if ((_internal_metadata_.have_unknown_fields() &&  ::google::protobuf::internal::GetProto3PreserveUnknownsDefault())) {
    target = ::google::protobuf::internal::WireFormat::SerializeUnknownFieldsToArray(
        (::google::protobuf::internal::GetProto3PreserveUnknownsDefault()   ? _internal_metadata_.unknown_fields()   : _internal_metadata_.default_instance()), target);
  }
  // @@protoc_insertion_point(serialize_to_array_end:grpc_se.GrpcMsgTX)
  return target;
}

size_t GrpcMsgTX::ByteSizeLong() const {
// @@protoc_insertion_point(message_byte_size_start:grpc_se.GrpcMsgTX)
  size_t total_size = 0;

  if ((_internal_metadata_.have_unknown_fields() &&  ::google::protobuf::internal::GetProto3PreserveUnknownsDefault())) {
    total_size +=
      ::google::protobuf::internal::WireFormat::ComputeUnknownFieldsSize(
        (::google::protobuf::internal::GetProto3PreserveUnknownsDefault()   ? _internal_metadata_.unknown_fields()   : _internal_metadata_.default_instance()));
  }
  // bytes message = 1;
  if (this->message().size() > 0) {
    total_size += 1 +
      ::google::protobuf::internal::WireFormatLite::BytesSize(
        this->message());
  }

  int cached_size = ::google::protobuf::internal::ToCachedSize(total_size);
  SetCachedSize(cached_size);
  return total_size;
}

void GrpcMsgTX::MergeFrom(const ::google::protobuf::Message& from) {
// @@protoc_insertion_point(generalized_merge_from_start:grpc_se.GrpcMsgTX)
  GOOGLE_DCHECK_NE(&from, this);
  const GrpcMsgTX* source =
      ::google::protobuf::internal::DynamicCastToGenerated<const GrpcMsgTX>(
          &from);
  if (source == NULL) {
  // @@protoc_insertion_point(generalized_merge_from_cast_fail:grpc_se.GrpcMsgTX)
    ::google::protobuf::internal::ReflectionOps::Merge(from, this);
  } else {
  // @@protoc_insertion_point(generalized_merge_from_cast_success:grpc_se.GrpcMsgTX)
    MergeFrom(*source);
  }
}

void GrpcMsgTX::MergeFrom(const GrpcMsgTX& from) {
// @@protoc_insertion_point(class_specific_merge_from_start:grpc_se.GrpcMsgTX)
  GOOGLE_DCHECK_NE(&from, this);
  _internal_metadata_.MergeFrom(from._internal_metadata_);
  ::google::protobuf::uint32 cached_has_bits = 0;
  (void) cached_has_bits;

  if (from.message().size() > 0) {

    message_.AssignWithDefault(&::google::protobuf::internal::GetEmptyStringAlreadyInited(), from.message_);
  }
}

void GrpcMsgTX::CopyFrom(const ::google::protobuf::Message& from) {
// @@protoc_insertion_point(generalized_copy_from_start:grpc_se.GrpcMsgTX)
  if (&from == this) return;
  Clear();
  MergeFrom(from);
}

void GrpcMsgTX::CopyFrom(const GrpcMsgTX& from) {
// @@protoc_insertion_point(class_specific_copy_from_start:grpc_se.GrpcMsgTX)
  if (&from == this) return;
  Clear();
  MergeFrom(from);
}

bool GrpcMsgTX::IsInitialized() const {
  return true;
}

void GrpcMsgTX::Swap(GrpcMsgTX* other) {
  if (other == this) return;
  InternalSwap(other);
}
void GrpcMsgTX::InternalSwap(GrpcMsgTX* other) {
  using std::swap;
  message_.Swap(&other->message_, &::google::protobuf::internal::GetEmptyStringAlreadyInited(),
    GetArenaNoVirtual());
  _internal_metadata_.Swap(&other->_internal_metadata_);
}

::google::protobuf::Metadata GrpcMsgTX::GetMetadata() const {
  protobuf_protobuf_5fse_2eproto::protobuf_AssignDescriptorsOnce();
  return ::protobuf_protobuf_5fse_2eproto::file_level_metadata[kIndexInFileMessages];
}


// ===================================================================

void Nothing::InitAsDefaultInstance() {
}
#if !defined(_MSC_VER) || _MSC_VER >= 1900
#endif  // !defined(_MSC_VER) || _MSC_VER >= 1900

Nothing::Nothing()
  : ::google::protobuf::Message(), _internal_metadata_(NULL) {
  ::google::protobuf::internal::InitSCC(
      &protobuf_protobuf_5fse_2eproto::scc_info_Nothing.base);
  SharedCtor();
  // @@protoc_insertion_point(constructor:grpc_se.Nothing)
}
Nothing::Nothing(const Nothing& from)
  : ::google::protobuf::Message(),
      _internal_metadata_(NULL) {
  _internal_metadata_.MergeFrom(from._internal_metadata_);
  // @@protoc_insertion_point(copy_constructor:grpc_se.Nothing)
}

void Nothing::SharedCtor() {
}

Nothing::~Nothing() {
  // @@protoc_insertion_point(destructor:grpc_se.Nothing)
  SharedDtor();
}

void Nothing::SharedDtor() {
}

void Nothing::SetCachedSize(int size) const {
  _cached_size_.Set(size);
}
const ::google::protobuf::Descriptor* Nothing::descriptor() {
  ::protobuf_protobuf_5fse_2eproto::protobuf_AssignDescriptorsOnce();
  return ::protobuf_protobuf_5fse_2eproto::file_level_metadata[kIndexInFileMessages].descriptor;
}

const Nothing& Nothing::default_instance() {
  ::google::protobuf::internal::InitSCC(&protobuf_protobuf_5fse_2eproto::scc_info_Nothing.base);
  return *internal_default_instance();
}


void Nothing::Clear() {
// @@protoc_insertion_point(message_clear_start:grpc_se.Nothing)
  ::google::protobuf::uint32 cached_has_bits = 0;
  // Prevent compiler warnings about cached_has_bits being unused
  (void) cached_has_bits;

  _internal_metadata_.Clear();
}

bool Nothing::MergePartialFromCodedStream(
    ::google::protobuf::io::CodedInputStream* input) {
#define DO_(EXPRESSION) if (!GOOGLE_PREDICT_TRUE(EXPRESSION)) goto failure
  ::google::protobuf::uint32 tag;
  // @@protoc_insertion_point(parse_start:grpc_se.Nothing)
  for (;;) {
    ::std::pair<::google::protobuf::uint32, bool> p = input->ReadTagWithCutoffNoLastTag(127u);
    tag = p.first;
    if (!p.second) goto handle_unusual;
  handle_unusual:
    if (tag == 0) {
      goto success;
    }
    DO_(::google::protobuf::internal::WireFormat::SkipField(
          input, tag, _internal_metadata_.mutable_unknown_fields()));
  }
success:
  // @@protoc_insertion_point(parse_success:grpc_se.Nothing)
  return true;
failure:
  // @@protoc_insertion_point(parse_failure:grpc_se.Nothing)
  return false;
#undef DO_
}

void Nothing::SerializeWithCachedSizes(
    ::google::protobuf::io::CodedOutputStream* output) const {
  // @@protoc_insertion_point(serialize_start:grpc_se.Nothing)
  ::google::protobuf::uint32 cached_has_bits = 0;
  (void) cached_has_bits;

  if ((_internal_metadata_.have_unknown_fields() &&  ::google::protobuf::internal::GetProto3PreserveUnknownsDefault())) {
    ::google::protobuf::internal::WireFormat::SerializeUnknownFields(
        (::google::protobuf::internal::GetProto3PreserveUnknownsDefault()   ? _internal_metadata_.unknown_fields()   : _internal_metadata_.default_instance()), output);
  }
  // @@protoc_insertion_point(serialize_end:grpc_se.Nothing)
}

::google::protobuf::uint8* Nothing::InternalSerializeWithCachedSizesToArray(
    bool deterministic, ::google::protobuf::uint8* target) const {
  (void)deterministic; // Unused
  // @@protoc_insertion_point(serialize_to_array_start:grpc_se.Nothing)
  ::google::protobuf::uint32 cached_has_bits = 0;
  (void) cached_has_bits;

  if ((_internal_metadata_.have_unknown_fields() &&  ::google::protobuf::internal::GetProto3PreserveUnknownsDefault())) {
    target = ::google::protobuf::internal::WireFormat::SerializeUnknownFieldsToArray(
        (::google::protobuf::internal::GetProto3PreserveUnknownsDefault()   ? _internal_metadata_.unknown_fields()   : _internal_metadata_.default_instance()), target);
  }
  // @@protoc_insertion_point(serialize_to_array_end:grpc_se.Nothing)
  return target;
}

size_t Nothing::ByteSizeLong() const {
// @@protoc_insertion_point(message_byte_size_start:grpc_se.Nothing)
  size_t total_size = 0;

  if ((_internal_metadata_.have_unknown_fields() &&  ::google::protobuf::internal::GetProto3PreserveUnknownsDefault())) {
    total_size +=
      ::google::protobuf::internal::WireFormat::ComputeUnknownFieldsSize(
        (::google::protobuf::internal::GetProto3PreserveUnknownsDefault()   ? _internal_metadata_.unknown_fields()   : _internal_metadata_.default_instance()));
  }
  int cached_size = ::google::protobuf::internal::ToCachedSize(total_size);
  SetCachedSize(cached_size);
  return total_size;
}

void Nothing::MergeFrom(const ::google::protobuf::Message& from) {
// @@protoc_insertion_point(generalized_merge_from_start:grpc_se.Nothing)
  GOOGLE_DCHECK_NE(&from, this);
  const Nothing* source =
      ::google::protobuf::internal::DynamicCastToGenerated<const Nothing>(
          &from);
  if (source == NULL) {
  // @@protoc_insertion_point(generalized_merge_from_cast_fail:grpc_se.Nothing)
    ::google::protobuf::internal::ReflectionOps::Merge(from, this);
  } else {
  // @@protoc_insertion_point(generalized_merge_from_cast_success:grpc_se.Nothing)
    MergeFrom(*source);
  }
}

void Nothing::MergeFrom(const Nothing& from) {
// @@protoc_insertion_point(class_specific_merge_from_start:grpc_se.Nothing)
  GOOGLE_DCHECK_NE(&from, this);
  _internal_metadata_.MergeFrom(from._internal_metadata_);
  ::google::protobuf::uint32 cached_has_bits = 0;
  (void) cached_has_bits;

}

void Nothing::CopyFrom(const ::google::protobuf::Message& from) {
// @@protoc_insertion_point(generalized_copy_from_start:grpc_se.Nothing)
  if (&from == this) return;
  Clear();
  MergeFrom(from);
}

void Nothing::CopyFrom(const Nothing& from) {
// @@protoc_insertion_point(class_specific_copy_from_start:grpc_se.Nothing)
  if (&from == this) return;
  Clear();
  MergeFrom(from);
}

bool Nothing::IsInitialized() const {
  return true;
}

void Nothing::Swap(Nothing* other) {
  if (other == this) return;
  InternalSwap(other);
}
void Nothing::InternalSwap(Nothing* other) {
  using std::swap;
  _internal_metadata_.Swap(&other->_internal_metadata_);
}

::google::protobuf::Metadata Nothing::GetMetadata() const {
  protobuf_protobuf_5fse_2eproto::protobuf_AssignDescriptorsOnce();
  return ::protobuf_protobuf_5fse_2eproto::file_level_metadata[kIndexInFileMessages];
}


// @@protoc_insertion_point(namespace_scope)
}  // namespace grpc_se
namespace google {
namespace protobuf {
template<> GOOGLE_PROTOBUF_ATTRIBUTE_NOINLINE ::grpc_se::GrpcMsgTX* Arena::CreateMaybeMessage< ::grpc_se::GrpcMsgTX >(Arena* arena) {
  return Arena::CreateInternal< ::grpc_se::GrpcMsgTX >(arena);
}
template<> GOOGLE_PROTOBUF_ATTRIBUTE_NOINLINE ::grpc_se::Nothing* Arena::CreateMaybeMessage< ::grpc_se::Nothing >(Arena* arena) {
  return Arena::CreateInternal< ::grpc_se::Nothing >(arena);
}
}  // namespace protobuf
}  // namespace google

// @@protoc_insertion_point(global_scope)
