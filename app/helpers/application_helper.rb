module ApplicationHelper

  def active_link_helper controller
    class_name =  params[:controller] == controller ? 'text-blue-700' : 'text-slate-700'
    return class_name
  end

end
