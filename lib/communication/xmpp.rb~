require "rubygems"
require 'xmpp4r/client'
require 'base64'
require 'builder'

# Jabber::debug = true

module Communication
  class XMPP
# inicia conexao com jabber e fica recebendo xml, e escrevendo 
# na pasta "trunk/input" os xml...
    def initialize(config = nil, debug = nil) # user,pass)
      @config = config
      @debug = debug
      @cl = Jabber::Client.new(Jabber::JID.new(@config['xmpp']['username']))
      @is_connected = false
      __connenct()
    end

    # TODO: Fazer com que esse metodo apenas receba uma string com um payload
    def send_msg(issue = '', config = nil)
      @debug.info('Sending message ...')
      return true if issue.empty?
      return false if !@is_connected
      begin
        msg = Jabber::Message.new(@config['xmpp']['importer_address'], product_xml(issue, config))
        msg.type = :normal
        @cl.send(msg)
      rescue
        @debug.error('Send message error')
        return false
      end

      sleep @config['xmpp']['send_delay'].to_f
      return true
    end

    def product_xml(issue, config)
#      issue[:_hash]
#      issue[:name]
#      issue[:description]
#      issue[:url]
#      issue[:cwe]
#      issue[:remedy_guidance]
#      issue[:cwe_url]
      xml = Builder::XmlMarkup.new( :ident => 2)
      xml.instruct! :xml, :encoding => 'ASCII'

      xml.scan do |s|
        s.header do |h|
          h.tool 'openvas'
          h.scope config['client']
          h.project config['project_id']
          h.timestamp Time.now
        end

        s.vulnerabilities do |vs|
          vs.vulnerability do |v|
            v.hash issue[:_hash]
            v.title Base64.encode64(issue[:name].to_s)
            v.description Base64.encode64("#{issue[:url]} \n\n #{issue[:description]}")
            v.optional do |vo|
              vo.affected_component Base64.encode64(issue[:affected_component])
              vo.control Base64.encode64("#{issue[:remedy_guidance]} \n #{issue[:remedy_code]}")
              vo.reference Base64.encode64(issue[:reference].to_s)
              vo.reproduction Base64.encode64("#{issue[:cwe]} - #{issue[:cwe_url]}")
              vo.exploitability issue[:severity].to_s.downcase
              vo.template_id issue[:template_id].to_s.downcase
            end
          end
        end
      end
    end

    def is_connected?
      @is_connected
    end

    private
    def __connenct
      begin
        @cl.connect
        @cl.auth(@config['xmpp']['password'])
        @cl.send(Jabber::Presence.new.set_type(:available))
        @is_connected = true
      rescue
        @debug.error('Cannot connect to XMPP server. Please check network connection and XMPP credentials.')
      end 
    end
  end

end
