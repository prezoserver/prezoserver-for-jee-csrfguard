/**
 * The OWASP CSRFGuard Project, BSD License
 * Eric Sheridan (eric@infraredsecurity.com), Copyright (c) 2011 
 * All rights reserved.
 * 
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 *    1. Redistributions of source code must retain the above copyright notice,
 *       this list of conditions and the following disclaimer.
 *    2. Redistributions in binary form must reproduce the above copyright
 *       notice, this list of conditions and the following disclaimer in the
 *       documentation and/or other materials provided with the distribution.
 *    3. Neither the name of OWASP nor the names of its contributors may be used
 *       to endorse or promote products derived from this software without specific
 *       prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON
 * ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
 * SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */
package org.owasp.csrfguard.servlet;

import java.io.IOException;
import java.io.OutputStream;
import java.io.PrintWriter;
import java.util.Iterator;
import java.util.Map;

import javax.servlet.ServletConfig;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;

import org.owasp.csrfguard.CsrfGuard;
import org.owasp.csrfguard.CsrfGuardServletContextListener;
import org.owasp.csrfguard.util.Streams;
import org.owasp.csrfguard.util.Strings;
import org.owasp.csrfguard.util.Writers;

public final class TokenServlet extends HttpServlet {
	private static final long serialVersionUID = 3548167874194090144L;
	
	private static ServletConfig servletConfig = null;

	public static ServletConfig getStaticServletConfig() {
		return servletConfig;
	}
	
	@Override
	public void init(ServletConfig theServletConfig) {
	  servletConfig = theServletConfig;
	  //print again since it might change based on servlet config of javascript servlet
	  CsrfGuardServletContextListener.printConfigIfConfigured(servletConfig.getServletContext(), 
			  "TokenServlet has now been initialized: ");
	}

	@Override
	public void doGet(HttpServletRequest request, HttpServletResponse response) throws IOException {
		throw new IOException("GET method not supported. Use POST instead.");
	}

	@Override
	public void doPost(HttpServletRequest request, HttpServletResponse response) throws IOException {
		CsrfGuard csrfGuard = CsrfGuard.getInstance();
		String isFetchCsrfToken = request.getHeader("FETCH-CSRF-TOKEN");
		
		if (csrfGuard != null && isFetchCsrfToken != null){
			fetchCsrfToken(request, response);
		} else {
			if (csrfGuard != null && csrfGuard.isTokenPerPageEnabled()) {
				writePageTokens(request, response);
			} else {
				response.sendError(404);
			}
		}
	}

	private void fetchCsrfToken(HttpServletRequest request, HttpServletResponse response) throws IOException {
		HttpSession session = request.getSession(true);
		CsrfGuard csrfGuard = CsrfGuard.getInstance();
		String token_name = csrfGuard.getTokenName();
		String token_value = (String) session.getAttribute(csrfGuard.getSessionKey());
		String token_pair = token_name + ":" + token_value;

		/** setup headers **/
		response.setContentType("text/plain");

		/** write dynamic javascript **/
		OutputStream output = null;
		PrintWriter writer = null;

		try {
			output = response.getOutputStream();
			writer = new PrintWriter(output);

			writer.write(token_pair);
			writer.flush();
		} finally {
			Writers.close(writer);
			Streams.close(output);
		}
	}

	private void writePageTokens(HttpServletRequest request, HttpServletResponse response) throws IOException {
		HttpSession session = request.getSession(true);
		@SuppressWarnings("unchecked")
		Map<String, String> pageTokens = (Map<String, String>) session.getAttribute(CsrfGuard.PAGE_TOKENS_KEY);
		String pageTokensString = (pageTokens != null ? parsePageTokens(pageTokens) : Strings.EMPTY);

		/** setup headers **/
		response.setContentType("text/plain");
		response.setContentLength(pageTokensString.length());

		/** write dynamic javascript **/
		OutputStream output = null;
		PrintWriter writer = null;

		try {
			output = response.getOutputStream();
			writer = new PrintWriter(output);

			writer.write(pageTokensString);
			writer.flush();
		} finally {
			Writers.close(writer);
			Streams.close(output);
		}
	}

	private String parsePageTokens(Map<String, String> pageTokens) {
		StringBuilder sb = new StringBuilder();
		Iterator<String> keys = pageTokens.keySet().iterator();

		while (keys.hasNext()) {
			String key = keys.next();
			String value = pageTokens.get(key);

			sb.append(key);
			sb.append(':');
			sb.append(value);

			if (keys.hasNext()) {
				sb.append(',');
			}
		}

		return sb.toString();
	}

}
