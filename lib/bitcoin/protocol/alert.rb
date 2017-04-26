# encoding: ascii-8bit

module Bitcoin
module Protocol

  class Alert < Struct.new(:version, :relay_until, :expiration, :id, :cancel, :set_cancel,
                           :min_ver, :max_ver, :set_sub_ver, :priority, :comment, :status_bar, :reserved)

    attr_accessor :payload, :signature

    def initialize(values, alert_payload=nil, alert_signature=nil)
      @payload, @signature = alert_payload, alert_signature
      super(*values)
    end

    def valid_signature?
      return false unless @payload && @signature
      hash = Digest::SHA256.digest(Digest::SHA256.digest(@payload))
      Bitcoin.network[:alert_pubkeys].any?{|public_key| Bitcoin.verify_signature(hash, @signature, public_key) }
    end


    def self.parse(payload)
      count,             payload = Bitcoin::Protocol.unpack_var_int(payload)
      alert_payload,     payload = payload.unpack("a#{count}a*")
      count,             payload = Bitcoin::Protocol.unpack_var_int(payload)
      alert_signature,   payload = payload.unpack("a#{count}a*")

      version, relay_until, expiration, id, cancel, payload = alert_payload.unpack("VQQVVa*")

      set_cancel,        payload = Bitcoin::Protocol.unpack_var_int_array(payload)
      min_ver, max_ver,  payload = payload.unpack("VVa*")
      set_sub_ver,       payload = Bitcoin::Protocol.unpack_var_string_array(payload)
      priority,          payload = payload.unpack("Va*")
      comment,           payload = Bitcoin::Protocol.unpack_var_string(payload)
      # fix:
      # require 'bitcoin'
      # Bitcoin::Protocol::Alert.parse(["60010000000000000000000000ffffff7f00000000ffffff7ffeffff7f01ffffff7f00000000ffffff7f00ffffff7f002f555247454e543a20416c657274206b657920636f6d70726f6d697365642c2075706772616465207265717569726564004630440220653febd6410f470f6bae11cad19c48413becb1ac2c17f908fd0fd53bdc3abd5202206d0e9c96fe88d4a0f01ed9dedae2b6f9e00da94cad0fecaae66ecf689bf71b50"].pack('H*'))
      if payload == "" then
        status_bar = ""
        reserved = ""
      else
        status_bar,        payload = Bitcoin::Protocol.unpack_var_string(payload)
        reserved,          payload = Bitcoin::Protocol.unpack_var_string(payload)
      end


      values = [ version, relay_until, expiration, id, cancel, set_cancel, min_ver, max_ver, set_sub_ver, priority, comment, status_bar, reserved ]

      new(values, alert_payload, alert_signature)
    end
  end

end
end
