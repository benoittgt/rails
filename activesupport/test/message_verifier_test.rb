require 'abstract_unit'

begin
  require 'openssl'
  OpenSSL::Digest::SHA1
rescue LoadError, NameError
  $stderr.puts "Skipping MessageVerifier test: broken OpenSSL install"
else

require 'active_support/time'
require 'active_support/json'

class MessageVerifierTest < ActiveSupport::TestCase

  class JSONSerializer
    def dump(value)
      ActiveSupport::JSON.encode(value)
    end

    def load(value)
      ActiveSupport::JSON.decode(value)
    end
  end

  def setup
    @verifier = ActiveSupport::MessageVerifier.new("Hey, I'm a secret!")
    @data = { :some => "data", :now => Time.local(2010) }
  end

  def test_simple_round_tripping
    message = @verifier.generate(@data)
    assert_equal @data, @verifier.verify(message)
  end

  def test_missing_signature_raises
    assert_not_verified(nil)
    assert_not_verified("")
  end

  def test_tampered_data_raises
    data, hash = @verifier.generate(@data).split("--")
    assert_not_verified("#{data.reverse}--#{hash}")
    assert_not_verified("#{data}--#{hash.reverse}")
    assert_not_verified("purejunk")
    assert_not_verified("\xff") # invalid encoding
  end

  def test_alternative_serialization_method
    prev = ActiveSupport.use_standard_json_time_format
    ActiveSupport.use_standard_json_time_format = true
    verifier = ActiveSupport::MessageVerifier.new("Hey, I'm a secret!", :serializer => JSONSerializer.new)
    message = verifier.generate({ :foo => 123, 'bar' => Time.utc(2010) })
    exp = { "foo" => 123, "bar" => "2010-01-01T00:00:00.000Z" }
    assert_equal exp, verifier.verify(message)
  ensure
    ActiveSupport.use_standard_json_time_format = prev
  end

  def test_raise_error_when_argument_class_is_not_loaded
    # To generate the valid message below:
    #
    #   AutoloadClass = Struct.new(:foo)
    #   valid_message = @verifier.generate(foo: AutoloadClass.new('foo'))
    #
    valid_message = "BAh7BjoIZm9vbzonTWVzc2FnZVZlcmlmaWVyVGVzdDo6QXV0b2xvYWRDbGFzcwY6CUBmb29JIghmb28GOgZFVA==--f3ef39a5241c365083770566dc7a9eb5d6ace914"
    exception = assert_raise(ArgumentError, NameError) do
      @verifier.verify(valid_message)
    end
    assert_includes ["uninitialized constant MessageVerifierTest::AutoloadClass",
                    "undefined class/module MessageVerifierTest::AutoloadClass"], exception.message
  end

  def test_raise_error_when_secret_is_nil
    exception = assert_raise(ArgumentError) do
      ActiveSupport::MessageVerifier.new(nil)
    end
    assert_equal exception.message, 'Secret should not be nil.'
  end

  def assert_not_verified(message)
    assert_raise(ActiveSupport::MessageVerifier::InvalidSignature) do
      @verifier.verify(message)
    end
  end

  def test_with_128_bytes_key
    # key = (0...128).map { ('a'..'z').to_a[rand(26)] }.join
    # encoded_text = ActiveSupport::MessageEncryptor.new(key).encrypt_and_sign("MyTextIsLong")
    key = "pwtzaphqnilfzzhujnyrjtwpaqnesshsqqievcvawmketkkxpkwptkkmnlhprnbqyfnzbycvzfibnrbfpufvwzkksehndofrmdamgogxouauxbpzvwxbqsjnrhctewmv"
    encoded_text = "SkpxZUZCWEFFeWpOQ3JDYkE0aWVkM1E5dlNPYlRTRlpuZkthb3RFZmpBcz0tLUR2MVErZ1YxSzRHQXRiSzk5YTBQU0E9PQ==--5e973448bacbf2c96a8cc27279ae4e77c5500ed2"
    assert_equal 'MyTextIsLong', ActiveSupport::MessageEncryptor.new(key[0..31]).decrypt_and_verify(encoded_text)
  end
end

end
