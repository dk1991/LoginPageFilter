package servlet;

import bean.UserAccount;
import utils.AppUtils;
import utils.DataDAO;

import javax.servlet.RequestDispatcher;
import javax.servlet.ServletException;
import javax.servlet.annotation.WebServlet;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

@WebServlet("/login")
public class LoginServlet extends HttpServlet {
    private static final long serialVersionUID = 1L;

    public LoginServlet() {
        super();
    }

    @Override
    protected void doGet(HttpServletRequest req, HttpServletResponse resp) throws ServletException, IOException {
        RequestDispatcher dispatcher = this.getServletContext().getRequestDispatcher("/WEB-INF/views/loginView.jsp");

        dispatcher.forward(req,resp);
    }

    @Override
    protected void doPost(HttpServletRequest req, HttpServletResponse resp) throws ServletException, IOException {
        String userName = req.getParameter("userName");
        String password = req.getParameter("password");
        UserAccount userAccount = DataDAO.findUser(userName, password);

        if (userAccount == null) {
            String errorMessage = "Invalid userName or Password";

            req.setAttribute("errorMessage",errorMessage);

            RequestDispatcher dispatcher = this.getServletContext().getRequestDispatcher("/WEB-INF/views/loginView.jsp");

            dispatcher.forward(req,resp);
            return;
        }

        AppUtils.storeLoginedUser(req.getSession(), userAccount);

        int redirectId = -1;
        try {
            redirectId = Integer.parseInt(req.getParameter("redirectId"));
        } catch (Exception e) {
        }
        String requestUri = AppUtils.getRedirectAfterLoginUrl(req.getSession(),redirectId);
        if (requestUri != null) {
            resp.sendRedirect(requestUri);
        } else {
            // По умолчанию после успешного входа в систему
            // перенаправить на страницу /userInfo
            resp.sendRedirect(req.getContextPath() + "/userInfo");
        }
    }
}
