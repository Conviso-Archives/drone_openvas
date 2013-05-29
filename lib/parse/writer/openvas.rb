
require 'base64'
require 'builder'

module Parse
  module Writer
    class Conviso
      def self.build_xml(issue, config)
        xml = Builder::XmlMarkup.new( :ident => 2)
        xml.instruct! :xml, :encoding => 'ASCII'

        xml.scan do |s|
          s.header do |h|
            h.tool "OpenVAS"
            h.scope config['client']
            h.project config['project_id']
            h.timestamp Time.now
          end

          
          s.vulnerabilities do |vs|
            vs.vulnerability('id' => issue['hash'] ) do |v|
              v.hash issue['hash']
              v.title issue[:name]
              v.description issue[:description]
            end # vulnerability
          end # vulnerabilities
        end # scan

      end

    end
  end
end



