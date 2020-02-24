package filter;

import bean.UserAccount;
import request.UserRoleRequestWrapper;
import utils.AppUtils;
import utils.SecurityUtils;

import javax.servlet.*;
import javax.servlet.annotation.WebFilter;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.List;

/*
SecurityFilter является  Servlet Filter, который выполняет обязанность проверки всех
request перед тем как позволить получить доступ в защищенные страницы (page).

SecurityFilter читает  "конфигурации безопасности" объявленные в классе  SecurityConfig
 */
@WebFilter("/*")
public class SecurityFilter implements Filter {
    public SecurityFilter() {
    }

    public void destroy() {
    }

    public void doFilter(ServletRequest servletRequest, ServletResponse servletResponse, FilterChain filterChain) throws IOException, ServletException {
        HttpServletRequest request = (HttpServletRequest) servletRequest;
        HttpServletResponse response = (HttpServletResponse) servletResponse;

        String servletPath = request.getServletPath();

        // Информация пользователя сохранена в Session
        // (После успешного входа в систему).
        UserAccount loginedUser = AppUtils.getLoginedUser(request.getSession());

        if (servletPath.equals("/login")) {
            filterChain.doFilter(request,response);
            return;
        }
        HttpServletRequest wrapRequest = request;

        if (loginedUser != null) {
            // User Name
            String userName = loginedUser.getUserName();

            // Роли (Role).
            List<String> roles = loginedUser.getRoles();

            // Старый пакет request с помощью нового Request с информацией userName и Roles.
            wrapRequest = new UserRoleRequestWrapper(userName, roles, request);
        }

        // Страницы требующие входа в систему.
        if (SecurityUtils.isSecurityPage(request)) {

            // Если пользователь еще не вошел в систему,
            // Redirect (перенаправить) к странице логина.
            if (loginedUser == null) {

                String requestUri = request.getRequestURI();

                // Сохранить текущую страницу для перенаправления (redirect) после успешного входа в систему.
                int redirectId = AppUtils.storeRedirectAfterLoginUrl(request.getSession(), requestUri);

                response.sendRedirect(wrapRequest.getContextPath() + "/login?redirectId=" + redirectId);
                return;
            }

            // Проверить пользователь имеет действительную роль или нет?
            boolean hasPermission = SecurityUtils.hasPermission(wrapRequest);
            if (!hasPermission) {

                RequestDispatcher dispatcher //
                        = request.getServletContext().getRequestDispatcher("/WEB-INF/views/accessDeniedView.jsp");

                dispatcher.forward(request, response);
                return;
            }
        }

        filterChain.doFilter(wrapRequest, response);
    }

    public void init(FilterConfig filterConfig) throws ServletException {

    }
}
