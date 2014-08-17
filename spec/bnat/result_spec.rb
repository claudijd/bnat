require 'bnat'
require 'rspec/its'

module BNAT
  describe Result do
    before :each do
      @helper = class Helper
                  include BNAT::Common
                end.new

      @request_pkt = @helper.get_tcp_packet
      @response_pkt = @helper.get_tcp_packet
      
      @result = BNAT::Result.new(
                  @request_pkt,
                  @response_pkt
                )
    end

    subject{@result}

    it "should generate a hash result" do
      subject.to_hash.should be_kind_of(::Hash)  
    end

    it "should generate a parsable JSON result" do
      JSON.parse(subject.to_json).should be_kind_of(::Hash)
    end

    it "should generate a parsable XML result" do
      Nokogiri::XML(subject.to_xml).should be_kind_of(Nokogiri::XML::Document)
    end 
  end
end